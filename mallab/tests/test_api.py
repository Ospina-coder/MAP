"""Pruebas HTTP, aislamiento por usuario, publicación y ejecución de tareas."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import transaction
from django.test import Client, TransactionTestCase, override_settings
from django.urls import reverse

from mallab.models import AnalysisReport, Sample, User
from mallab.tasks import analyze_sample_task


class SampleAPITests(TransactionTestCase):
    """Usa commits reales para comprobar el callback que publica en Celery."""

    def setUp(self):
        self.media = TemporaryDirectory()
        self.addCleanup(self.media.cleanup)
        override = override_settings(MEDIA_ROOT=self.media.name, YARA_RULES_DIR=None)
        override.enable()
        self.addCleanup(override.disable)
        self.user = User.objects.create_user(username="owner", email="owner@example.test", name="Owner")
        self.other = User.objects.create_user(username="other", email="other@example.test", name="Other")
        self.client.force_login(self.user)
        self.upload_url = reverse("mallab:upload-sample")

    def upload(self, content=b"abc"):
        return self.client.post(self.upload_url, {"file": SimpleUploadedFile("test.exe", content)})

    def test_upload_commits_before_publication_and_does_not_analyze(self):
        def published(*, args, retry):
            self.assertFalse(transaction.get_connection().in_atomic_block)
            self.assertTrue(Sample.objects.filter(pk=args[0], uploaded_by=self.user).exists())
            self.assertEqual(AnalysisReport.objects.get(sample_id=args[0]).status, "PENDING")
            self.assertFalse(retry)

        with patch("mallab.views.analyze_sample_task.apply_async", side_effect=published) as dispatch:
            with patch("mallab.tasks.process_sample") as analyze:
                response = self.upload()
        self.assertEqual(response.status_code, 202)
        dispatch.assert_called_once()
        analyze.assert_not_called()
        sample = Sample.objects.get()
        self.assertEqual(sample.file_size, 3)
        self.assertEqual(sample.uploaded_by, self.user)
        self.assertEqual(response["Location"], response.json()["report_url"])

    def test_size_limit_stops_upload_and_creates_no_records(self):
        with override_settings(SAMPLE_MAX_UPLOAD_BYTES=2):
            with patch("mallab.views.analyze_sample_task.apply_async") as dispatch:
                response = self.upload(b"abc")
        self.assertEqual(response.status_code, 413)
        self.assertFalse(Sample.objects.exists())
        self.assertFalse(AnalysisReport.objects.exists())
        self.assertFalse(list(Path(self.media.name).rglob("*")))
        dispatch.assert_not_called()

    def test_missing_multiple_files_and_wrong_content_type(self):
        self.assertEqual(self.client.post(self.upload_url, {}).status_code, 400)
        self.assertEqual(self.client.post(self.upload_url, {"file": [
            SimpleUploadedFile("a", b"a"), SimpleUploadedFile("b", b"b"),
        ]}).status_code, 400)
        self.assertEqual(self.client.post(self.upload_url, "{}", content_type="application/json").status_code, 415)
        self.assertEqual(self.client.get(self.upload_url).status_code, 405)
        self.assertFalse(Sample.objects.exists())

    def test_report_requires_authenticated_active_user(self):
        self.client.logout()
        self.assertEqual(self.client.get("/api/samples/1/report/").status_code, 401)
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        self.client.force_login(self.user)
        self.assertEqual(self.client.get("/api/samples/1/report/").status_code, 401)

    def test_upload_without_csrf_returns_sample_id_and_status(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        with patch("mallab.views.analyze_sample_task.apply_async"):
            response = client.post(self.upload_url, {"file": SimpleUploadedFile("a", b"a")})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(response.json()["sample_id"], Sample.objects.get().pk)
        self.assertEqual(response.json()["status"], "PENDING")

        client.logout()
        with patch("mallab.views.analyze_sample_task.apply_async") as dispatch:
            response = client.post(self.upload_url, {"file": SimpleUploadedFile("a", b"a")})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response["Content-Type"], "application/json")
        sample = Sample.objects.get(pk=response.json()["sample_id"])
        self.assertEqual(sample.uploaded_by, self.user)
        self.assertEqual(response.json()["status"], "PENDING")
        dispatch.assert_called_once_with(args=[sample.pk], retry=False)
        self.assertEqual(Sample.objects.count(), 2)
        self.assertEqual(client.get(response.json()["report_url"]).status_code, 401)
        client.force_login(self.user)
        self.assertEqual(client.get(response.json()["report_url"]).status_code, 200)
        client.force_login(self.other)
        self.assertEqual(client.get(response.json()["report_url"]).status_code, 404)

    def test_anonymous_upload_without_users_returns_json_error(self):
        self.client.logout()
        User.objects.all().delete()
        with patch("mallab.views.analyze_sample_task.apply_async") as dispatch:
            response = self.upload()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"], "upload_owner_unavailable")
        self.assertFalse(Sample.objects.exists())
        self.assertFalse(AnalysisReport.objects.exists())
        self.assertFalse([path for path in Path(self.media.name).rglob("*") if path.is_file()])
        dispatch.assert_not_called()

    def test_worker_results_and_owner_only_access(self):
        with patch("mallab.views.analyze_sample_task.apply_async"):
            response = self.upload()
        url = response.json()["report_url"]
        pending = self.client.get(url)
        self.assertEqual(pending.json()["status"], "PENDING")
        self.assertEqual(pending["Retry-After"], "3")
        self.assertNotIn("results", pending.json())
        report = AnalysisReport.objects.get()
        report.status = "PROCESSING"
        report.save(update_fields=["status"])
        self.assertEqual(self.client.get(url).json()["status"], "PROCESSING")
        report.status = "PENDING"
        report.save(update_fields=["status"])
        result = analyze_sample_task.run(response.json()["sample_id"])
        self.assertEqual(result["status"], "COMPLETED")
        data = self.client.get(url).json()
        self.assertEqual(data["status"], "COMPLETED")
        self.assertEqual(data["results"]["hashes"]["md5"], "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(data["results"]["pe_headers"]["is_pe"], False)
        self.assertEqual(data["results"]["yara"]["status"], "SKIPPED")
        self.assertNotIn("file", data)
        self.client.force_login(self.other)
        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(self.client.get("/api/samples/999999/report/").status_code, 404)

    def test_broker_failure_preserves_sample_and_marks_failed(self):
        with patch("mallab.views.analyze_sample_task.apply_async", side_effect=ConnectionError("private broker address")):
            with self.assertLogs("mallab.views", level="ERROR"):
                response = self.upload()
        self.assertEqual(response.status_code, 503)
        self.assertTrue(Sample.objects.exists())
        report = AnalysisReport.objects.get()
        self.assertEqual(report.status, "FAILED")
        data = self.client.get(response.json()["report_url"]).json()
        self.assertEqual(data["error"]["stage"], "enqueue")
        self.assertNotIn("private broker address", str(data))

    def test_database_failure_cleans_stored_file(self):
        with patch("mallab.views.AnalysisReport.objects.create", side_effect=RuntimeError("db error")):
            with self.assertRaises(RuntimeError):
                self.upload()
        self.assertFalse(Sample.objects.exists())
        self.assertFalse([path for path in Path(self.media.name).rglob("*") if path.is_file()])

    def test_deleted_and_duplicate_tasks(self):
        self.assertEqual(analyze_sample_task.run(999999)["status"], "DELETED")
        with patch("mallab.views.analyze_sample_task.apply_async"):
            response = self.upload()
        report = AnalysisReport.objects.get()
        report.status = "PROCESSING"
        report.save(update_fields=["status"])
        self.assertEqual(analyze_sample_task.run(response.json()["sample_id"])["status"], "PROCESSING")

    @override_settings(CELERY_BROKER_URL="memory://", CELERY_TASK_ALWAYS_EAGER=False)
    def test_real_celery_worker_consumes_committed_upload(self):
        """Prueba el despacho asíncrono sin necesitar un servicio Redis externo."""
        from threading import Event

        from celery.contrib.testing.worker import start_worker
        from celery.signals import task_postrun

        from config.celery import app

        completed = Event()

        def finished(sender=None, **kwargs):
            if sender.name == "mallab.tasks.analyze_sample_task":
                completed.set()

        task_postrun.connect(finished, weak=False)
        try:
            with start_worker(app, pool="solo", queues=["analysis"], perform_ping_check=False):
                response = self.upload()
                self.assertEqual(response.status_code, 202)
                self.assertTrue(completed.wait(10), "El worker no terminó la tarea")
                data = self.client.get(response.json()["report_url"]).json()
                self.assertEqual(data["status"], "COMPLETED")
        finally:
            task_postrun.disconnect(finished)
