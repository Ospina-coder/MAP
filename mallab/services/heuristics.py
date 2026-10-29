"""Indicadores estáticos explicables. No clasifica ni asigna probabilidades."""

import math

from .exceptions import AnalysisInputError


def evaluate_heuristics(*, file_size, entropy, pe, entropy_threshold=7.5, min_entropy_bytes=4096):
    """Los umbrales son criterios de revisión configurables, no calibraciones.

    Se consume únicamente metadata extraída de la misma instantánea analizada.
    Nunca se importan ni ejecutan funciones procedentes de la muestra.
    """
    if (isinstance(entropy_threshold, bool) or not isinstance(entropy_threshold, (int, float))
            or not math.isfinite(entropy_threshold) or not 0 <= entropy_threshold <= 8
            or isinstance(min_entropy_bytes, bool) or not isinstance(min_entropy_bytes, int)
            or min_entropy_bytes < 1):
        raise AnalysisInputError("Configuración inválida de umbrales heurísticos.")
    findings = []

    def add(identifier, description, evidence, rationale, limitations):
        findings.append({
            "id": identifier, "description": description, "evidence": evidence,
            "technical_rationale": rationale, "limitations": limitations,
        })

    if file_size >= min_entropy_bytes and entropy >= entropy_threshold:
        add("high_file_entropy", "Entropía global elevada según el criterio de revisión.",
            {"entropy_bits_per_byte": entropy, "size": file_size, "threshold": entropy_threshold,
             "minimum_bytes": min_entropy_bytes},
            "Una distribución de bytes cercana a uniforme puede acompañar compresión, cifrado o empaquetado.",
            "Archivos legítimos comprimidos o cifrados también producen este indicador; no demuestra malware.")

    if pe.get("reason") in {"invalid_pe", "malformed_pe"}:
        add("invalid_pe_structure", "La cabecera MZ no pudo interpretarse como un PE completo.",
            {"reason": pe["reason"]},
            "Una estructura incompatible o truncada reduce la fiabilidad de la interpretación del ejecutable.",
            "Puede ser un archivo DOS, corrupto o incompleto; la anomalía no demuestra intención maliciosa.")

    if pe.get("is_pe"):
        sections = pe.get("sections", [])
        for index, section in enumerate(sections):
            base = {"section_index": index, "name": section["name"]}
            flags = section.get("characteristics", 0)
            if flags & 0x20000000 and flags & 0x80000000:
                add("writable_executable_section", "Sección declarada escribible y ejecutable.",
                    {**base, "characteristics": flags},
                    "IMAGE_SCN_MEM_WRITE e IMAGE_SCN_MEM_EXECUTE permiten modificar bytes ejecutables.",
                    "JIT, protectores y empaquetadores legítimos pueden usar esos permisos.")
            raw_size = section.get("raw_size", 0)
            raw_offset = section.get("raw_offset", 0)
            if raw_size and raw_offset + raw_size > file_size:
                add("section_raw_out_of_bounds", "Una sección declara datos fuera del archivo.",
                    {**base, "raw_offset": raw_offset, "raw_size": raw_size, "file_size": file_size},
                    "PointerToRawData + SizeOfRawData supera la instantánea disponible.",
                    "Puede deberse a truncamiento o generación defectuosa; no identifica malware.")
            # Se usa el tamaño observado, no solo el declarado por el archivo.
            observed = section.get("observed_size", 0)
            if observed >= min_entropy_bytes and section.get("entropy", 0) >= entropy_threshold:
                add("high_section_entropy", "Entropía elevada en una sección suficientemente grande.",
                    {**base, "entropy_bits_per_byte": section["entropy"], "observed_size": observed,
                     "threshold": entropy_threshold, "minimum_bytes": min_entropy_bytes},
                    "Los bytes observados son compatibles con datos comprimidos, cifrados o empaquetados.",
                    "Recursos legítimos pueden tener el mismo patrón; no prueba empaquetado ni malware.")

        entry_point = pe.get("entry_point_rva", 0)
        if entry_point:
            containing = [section for section in sections if section.get("virtual_address", 0) <= entry_point
                          < section.get("virtual_address", 0) + max(section.get("virtual_size", 0), section.get("raw_size", 0))]
            if not any(section.get("characteristics", 0) & 0x20000000 for section in containing):
                add("entry_point_outside_executable_section", "Entry point fuera de las secciones declaradas ejecutables.",
                    {"entry_point_rva": entry_point, "containing_sections": [section["name"] for section in containing]},
                    "AddressOfEntryPoint no cae en una sección extraída con IMAGE_SCN_MEM_EXECUTE.",
                    "PE inusual, corrupción o protectores legítimos pueden explicar la estructura.")

        names = {function.get("name", "").casefold() for library in pe.get("imports", [])
                 for function in library.get("functions", []) if function.get("name")}
        combination = {"virtualallocex", "writeprocessmemory", "createremotethread"}
        if combination <= names:
            evidence = [
                {"dll": library["dll"], "function": function["name"]}
                for library in pe.get("imports", []) for function in library.get("functions", [])
                if function.get("name") and function["name"].casefold() in combination
            ]
            add("remote_process_memory_api_combination", "Combinación de imports para memoria y threads de otro proceso.",
                {"imports": evidence},
                "La combinación permite reservar memoria remota, escribirla y crear un thread remoto.",
                "Depuradores y herramientas de administración también la usan. Los imports no demuestran que se invoquen.")
        if pe.get("warnings"):
            add("pe_parser_warnings", "El parser comunicó advertencias de estructura PE.",
                {"warnings": pe["warnings"]},
                "Las advertencias documentan anomalías que pueden afectar a la interpretación estática.",
                "Son observaciones del parser, no firmas ni pruebas de comportamiento.")

    return {
        "status": "COMPLETED", "engine_version": 1,
        "parameters": {"entropy_threshold": entropy_threshold, "minimum_entropy_bytes": min_entropy_bytes},
        "findings": findings,
        "scope": {"pe_available": bool(pe.get("is_pe"))},
        "interpretation": "Indicadores de revisión sin puntuación, probabilidad ni veredicto de seguridad.",
    }
