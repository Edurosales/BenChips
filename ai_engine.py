"""
ai_engine.py — Motor de Inteligencia Artificial profesional.

ARQUITECTURA DE 3 LLAMADAS TOTALES (sin importar cuántas vulns haya):
  Llamada 1 — Mass Triage:    Analiza TODAS las vulns a la vez → JSON array
  Llamada 2 — Intelligence:   Síntesis ejecutiva + cadenas de ataque + tests avanzados
  Llamada 3 — Deep Dive:      PoC detallado + exploit chain de los hallazgos críticos

Esto permite:
  - Nunca superar el rate limit (3 llamadas vs 33+)
  - IA con contexto completo → detecta cadenas de ataque entre hallazgos
  - Más inteligente: correlaciona múltiples MEDIUM que forman un CRITICAL
  - 10x más rápido que el pipeline vuln-por-vuln
"""

from __future__ import annotations

import json
import os
import asyncio
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from utils.vuln import Vuln

_CONFIG_FILE = os.path.join(os.path.dirname(__file__), ".ai_config.json")


def load_ai_config() -> dict:
    if os.path.exists(_CONFIG_FILE):
        try:
            with open(_CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_ai_config(config: dict) -> None:
    with open(_CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


class AIEngine:
    """
    Motor AI profesional de 3 llamadas totales.
    Analiza con contexto completo — detecta cadenas de ataque entre hallazgos.
    """

    _token_budget_used: int = 0
    _calls_made: int = 0
    _semaphore = None

    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str = "gpt-4o-mini",
        session_token_limit: int = 80_000,
    ):
        self.api_key             = api_key.strip()
        self.base_url            = base_url.strip().rstrip("/")
        self.model               = model.strip()
        self.session_token_limit = session_token_limit
        self._available          = True

    # ── Petición base ──────────────────────────────────────────────────────────

    async def _chat(
        self,
        system: str,
        user: str,
        max_tokens: int = 4096,
        temperature: float = 0.1,
    ) -> Optional[str]:
        """Llamada base con reintentos, backoff y semáforo de concurrencia."""
        if not self._available:
            return None
        if self._token_budget_used >= self.session_token_limit:
            self._available = False
            return None

        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(3)

        import aiohttp

        payload = {
            "model":       self.model,
            "max_tokens":  max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        }

        endpoint = f"{self.base_url}/v1/chat/completions"
        if self.base_url.endswith("/v1/chat/completions"):
            endpoint = self.base_url
        elif self.base_url.endswith("/v1"):
            endpoint = f"{self.base_url}/chat/completions"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json",
            "User-Agent":    "BugBountyHunter/5.0 (Windows NT 10.0; Win64; x64)",
        }

        # Intentar hasta 15 veces para sortear el rate limit agresivo de forma transparente
        for attempt in range(15):
            async with self._semaphore:
                try:
                    connector = aiohttp.TCPConnector(ssl=False)
                    async with aiohttp.ClientSession(connector=connector) as sess:
                        async with sess.post(
                            endpoint, json=payload, headers=headers,
                            timeout=aiohttp.ClientTimeout(total=120)
                        ) as resp:
                            if resp.status == 429:
                                # Extraer tiempo de espera del header si existe
                                wait_time = resp.headers.get("Retry-After", resp.headers.get("x-ratelimit-reset"))
                                try:
                                    wait_time = float(wait_time) if wait_time else (2 ** attempt * 2)
                                except ValueError:
                                    wait_time = 2 ** attempt * 2
                                
                                # Si dice que esperemos demasiado, capamos a 60s max por intento para no colgar infinito
                                wait_time = min(max(wait_time + 1.0, 5.0), 60.0)
                                await asyncio.sleep(wait_time)
                                continue
                            
                            data = await resp.json(content_type=None)

                    usage = data.get("usage", {})
                    self._token_budget_used += usage.get("total_tokens", max_tokens // 3)
                    self._calls_made        += 1

                    if "error" in data:
                        err = data["error"].get("message", "").lower()
                        if "rate limit" in err:
                            # A veces el error de Groq dice "Please try again in 5.6s"
                            wait_time = 15.0
                            import re
                            match = re.search(r"try again in ([\d\.]+)s", err)
                            if match:
                                wait_time = float(match.group(1)) + 1.0
                            await asyncio.sleep(wait_time)
                            continue
                        if any(x in err for x in ("quota", "insufficient", "billing")):
                            self._available = False
                        return None

                    choices = data.get("choices", [])
                    if choices:
                        return choices[0]["message"]["content"].strip()

                except asyncio.TimeoutError:
                    await asyncio.sleep(2 ** attempt)
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                    await asyncio.sleep(2)

        raise Exception("API Limit reached / Connection failed después de 15 intentos.")

    def _parse_json(self, resp: str) -> Optional[dict | list]:
        """Extrae JSON de la respuesta (tolerante a markdown)."""
        if not resp:
            return None
        resp = resp.strip()
        for start_char in ["{", "["]:
            try:
                start = resp.index(start_char)
                end_char = "}" if start_char == "{" else "]"
                end = resp.rindex(end_char) + 1
                return json.loads(resp[start:end])
            except (ValueError, json.JSONDecodeError):
                continue
        if resp.startswith("```"):
            parts = resp.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:]
                try:
                    return json.loads(part.strip())
                except Exception:
                    continue
        return None

    # ── TEST DE CONEXIÓN ───────────────────────────────────────────────────────

    async def test_connection(self) -> tuple[bool, str]:
        resp = await self._chat(
            system="You are a security tool validator. Reply with exactly: OK",
            user="Reply with exactly: OK",
            max_tokens=256,
        )
        if resp and "OK" in resp:
            return True, f"Conectado. Modelo: {self.model}"
        return False, "No se pudo conectar. Verifica API key, URL y modelo."

    # ═══════════════════════════════════════════════════════════════════════════
    # LLAMADA 1 — TRIAJE MASIVO (una sola petición para todas las vulns)
    # ═══════════════════════════════════════════════════════════════════════════

    async def mass_triage(
        self,
        vulns: list["Vuln"],
        target_url: str,
        meta: dict,
    ) -> dict[str, dict]:
        """
        Analiza TODAS las vulnerabilidades en UNA SOLA llamada.
        Retorna dict[dedup_key -> análisis].
        """
        if not vulns:
            return {}

        server      = meta.get("server", "unknown")
        waf         = meta.get("waf") or "none"
        techs       = ", ".join(meta.get("technologies", [])[:8]) or "unknown"
        ips         = ", ".join(meta.get("ips", [])[:3]) or "unknown"

        # Construir lista compacta de hallazgos
        findings_list = []
        key_map = {}  # index → dedup_key
        for i, v in enumerate(vulns):
            key_map[i] = v.dedup_key
            findings_list.append({
                "id":       i,
                "key":      v.dedup_key,
                "title":    v.title,
                "severity": v.severity,
                "cvss":     v.cvss,
                "evidence": v.evidence[:150],
                "fix_hint": v.fix[:100],
            })

        system = """You are an elite offensive security researcher and bug bounty specialist.
Analyze ALL findings simultaneously. This gives you context to detect attack chains.

STRICT FALSE POSITIVE RULES — apply these automatically:
- "49 in response" → NEVER proves SSTI alone
- "Server: CloudFront" → INFO only, never higher
- 302 redirect to same domain → NOT open redirect
- CORS wildcard on PUBLIC CDN → INFO, intentional design
- Missing headers on CDN edge → LOW/INFO, set at origin
- IMDSv2 required on AWS since 2021 → direct metadata = FP
- Custom Engine template detection → almost certainly FP
- Identical error pages → not RCE

SEVERITY CALIBRATION:
- CRITICAL: RCE, SQLi with data extraction, auth bypass, account takeover chain
- HIGH: Stored XSS, SSRF with internal data, significant data exposure
- MEDIUM: Reflected XSS, CSRF, missing important headers
- LOW: Info disclosure, SameSite cookies, minor headers
- INFO: Banners, WAF absence, cosmetic issues

ATTACK CHAIN DETECTION: If you see XSS + cookie without HttpOnly → mark as HIGH chain.
If you see SSRF + cloud metadata → mark potential CRITICAL chain.

Respond with ONLY a JSON array (no markdown, no explanation):
[
  {
    "id": 0,
    "status": "CONFIRMED|FALSE_POSITIVE|DOWNGRADED",
    "final_severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO|REJECTED",
    "confidence": 85,
    "is_false_positive": false,
    "false_positive_reason": null,
    "business_impact": "realistic 1-sentence impact",
    "exploitability": "High|Medium|Low",
    "owasp_category": "A03:2021",
    "cwe_ids": ["CWE-79"],
    "bounty_estimate_usd": "500-2000",
    "detailed_fix": "specific remediation",
    "part_of_chain": null
  }
]"""

        user = f"""Target: {target_url}
Server: {server} | WAF: {waf} | Technologies: {techs} | IPs: {ips}

Findings to analyze ({len(findings_list)} total):
{json.dumps(findings_list, indent=2)}

Analyze ALL findings. Apply strict FP rules. Detect attack chains. Return JSON array."""

        resp = await self._chat(system, user, max_tokens=4096)
        parsed = self._parse_json(resp)

        results: dict[str, dict] = {}
        if isinstance(parsed, list):
            for item in parsed:
                idx = item.get("id")
                if idx is not None and idx in key_map:
                    results[key_map[idx]] = item
        elif isinstance(parsed, dict):
            # Some models return {"results": [...]}
            inner = parsed.get("results") or parsed.get("findings") or []
            for item in inner:
                idx = item.get("id")
                if idx is not None and idx in key_map:
                    results[key_map[idx]] = item

        return results

    # ═══════════════════════════════════════════════════════════════════════════
    # LLAMADA 2 — SÍNTESIS DE INTELIGENCIA
    # ═══════════════════════════════════════════════════════════════════════════

    async def intelligence_synthesis(
        self,
        target_url: str,
        confirmed_vulns: list["Vuln"],
        triage_results: dict[str, dict],
        meta: dict,
        duration: float,
    ) -> dict:
        """
        Una llamada para obtener TODO:
        - Resumen ejecutivo profesional
        - Cadenas de ataque detectadas
        - Tests avanzados priorizados
        - Evaluación del riesgo del negocio
        """
        from utils.vuln import count_by_severity, risk_score
        counts       = count_by_severity(confirmed_vulns)
        score, level = risk_score(counts)

        techs  = ", ".join(meta.get("technologies", [])[:8]) or "unknown"
        server = meta.get("server", "unknown")
        waf    = meta.get("waf") or "none"
        ports  = [p.get("port", "") for p in meta.get("ports", [])[:8]]

        confirmed_summary = []
        for v in confirmed_vulns[:15]:
            t = triage_results.get(v.dedup_key, {})
            confirmed_summary.append({
                "title":          v.title,
                "final_severity": t.get("final_severity", v.severity),
                "confidence":     t.get("confidence", "?"),
                "business_impact": t.get("business_impact", ""),
                "part_of_chain":  t.get("part_of_chain"),
            })

        system = """You are a senior bug bounty researcher writing a professional security report.
Respond ONLY with JSON (no markdown):
{
  "executive_summary": "4-6 professional sentences in Spanish summarizing the security posture, main risks, and recommendations",
  "risk_level_justification": "1 sentence explaining why this risk level",
  "attack_chains": [
    {
      "name": "Attack Chain Name",
      "steps": ["step 1", "step 2", "step 3"],
      "impact": "what an attacker achieves",
      "severity": "CRITICAL|HIGH|MEDIUM"
    }
  ],
  "advanced_tests": [
    "Specific test 1 with exact technique/tool",
    "Specific test 2"
  ],
  "quick_wins": ["High-impact fix 1", "High-impact fix 2"],
  "business_risk_summary": "1 paragraph in Spanish for non-technical stakeholders"
}"""

        user = f"""Security Assessment for: {target_url}
Server: {server} | WAF: {waf} | Technologies: {techs}
Open ports: {ports}
Scan duration: {duration:.1f}s
Risk level: {level} (score: {score})
Confirmed findings: CRITICAL={counts['CRITICAL']} HIGH={counts['HIGH']} MEDIUM={counts['MEDIUM']} LOW={counts['LOW']}

Confirmed vulnerabilities:
{json.dumps(confirmed_summary, indent=2)}

Generate intelligence synthesis with attack chains and advanced tests.
Respond ONLY with the JSON schema."""

        resp = await self._chat(system, user, max_tokens=2048, temperature=0.2)
        parsed = self._parse_json(resp)

        if isinstance(parsed, dict):
            return parsed
        return {
            "executive_summary":     "",
            "attack_chains":         [],
            "advanced_tests":        [],
            "quick_wins":            [],
            "business_risk_summary": "",
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # LLAMADA 3 — DEEP DIVE (PoC + exploit chain para hallazgos críticos)
    # ═══════════════════════════════════════════════════════════════════════════

    async def deep_dive_critical(
        self,
        critical_vulns: list["Vuln"],
        target_url: str,
        meta: dict,
    ) -> dict[str, dict]:
        """
        Análisis profundo de los hallazgos CRITICAL y HIGH.
        Genera PoC, exploit chain y pasos de verificación exactos.
        Solo se llama si hay hallazgos CRITICAL o HIGH.
        """
        if not critical_vulns:
            return {}

        top = critical_vulns[:5]
        techs  = ", ".join(meta.get("technologies", [])[:6]) or "unknown"
        server = meta.get("server", "unknown")

        findings_deep = []
        key_map = {}
        for i, v in enumerate(top):
            key_map[i] = v.dedup_key
            findings_deep.append({
                "id":       i,
                "title":    v.title,
                "category": v.category,
                "severity": v.severity,
                "evidence": v.evidence[:400],
                "desc":     v.description,
            })

        system = """You are an elite penetration tester writing exact PoC for bug bounty submissions.
For each finding, provide actionable verification steps that a reviewer can run.
Respond ONLY with JSON array (no markdown):
[
  {
    "id": 0,
    "poc_curl": "exact curl command to verify",
    "exploit_steps": ["step 1", "step 2", "step 3"],
    "impact_demo": "what to show/screenshot to prove impact",
    "remediation_code": "exact code fix or config change",
    "report_title": "professional bug bounty report title",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  }
]"""

        user = f"""Target: {target_url}
Server: {server} | Technologies: {techs}

Critical/High findings requiring deep analysis:
{json.dumps(findings_deep, indent=2)}

Generate exact PoC and exploitation steps for each. Respond ONLY with JSON array."""

        resp = await self._chat(system, user, max_tokens=2048)
        parsed = self._parse_json(resp)

        results: dict[str, dict] = {}
        if isinstance(parsed, list):
            for item in parsed:
                idx = item.get("id")
                if idx is not None and idx in key_map:
                    results[key_map[idx]] = item

        return results

    # ═══════════════════════════════════════════════════════════════════════════
    # FUNCIÓN PRINCIPAL — orquesta las 3 llamadas
    # ═══════════════════════════════════════════════════════════════════════════

    async def full_analysis(
        self,
        vulns: list["Vuln"],
        target_url: str,
        meta: dict,
        duration: float,
    ) -> dict:
        """
        Pipeline completo de 3 llamadas.
        Retorna un dict con toda la inteligencia generada.
        """
        from utils.colors import print_info, print_ok, print_warn, print_err, spinner_async

        result = {
            "triage":         {},
            "intelligence":   {},
            "deep_dive":      {},
            "exec_summary":   "",
            "attack_chains":  [],
            "advanced_tests": [],
            "quick_wins":     [],
        }

        if not vulns:
            return result

        try:
            # ── Llamada 1: Triaje masivo ─────────────────────────────────────────
            async with spinner_async(f"[1/3] Triaje masivo de {len(vulns)} hallazgos (1 llamada)"):
                triage = await self.mass_triage(vulns, target_url, meta)
            result["triage"] = triage

            # Aplicar resultados — filtrar falsos positivos
            false_positives = {k for k, v in triage.items() if v.get("is_false_positive")}
            confirmed = [v for v in vulns if v.dedup_key not in false_positives]
            fp_count  = len(vulns) - len(confirmed)

            if fp_count > 0:
                print_ok(f"    {fp_count} falsos positivos eliminados automáticamente")
            else:
                print_ok("    Sin falsos positivos detectados")

            if not confirmed:
                print_warn("    Sin hallazgos confirmados. Análisis de inteligencia omitido.")
                return result

            # Pausa breve entre llamadas (evitar rate limit)
            await asyncio.sleep(2)

            # ── Llamada 2: Síntesis de inteligencia ──────────────────────────────
            async with spinner_async(f"[2/3] Síntesis de inteligencia y cadenas de ataque ({len(confirmed)} confirmados)"):
                intel = await self.intelligence_synthesis(
                    target_url, confirmed, triage, meta, duration
                )
            result["intelligence"]   = intel
            result["exec_summary"]   = intel.get("executive_summary", "")
            result["attack_chains"]  = intel.get("attack_chains", [])
            result["advanced_tests"] = intel.get("advanced_tests", [])
            result["quick_wins"]     = intel.get("quick_wins", [])

            if result["exec_summary"]:
                print_ok("    Resumen ejecutivo generado")
            if result["attack_chains"]:
                print_ok(f"    {len(result['attack_chains'])} cadenas de ataque detectadas")

            # ── Llamada 3: Deep dive (solo si hay CRITICAL o HIGH) ───────────────
            critical_high = [
                v for v in confirmed
                if v.severity in ("CRITICAL", "HIGH")
            ]

            if critical_high:
                await asyncio.sleep(2)
                async with spinner_async(f"[3/3] Deep dive y PoC para {len(critical_high[:5])} hallazgos críticos"):
                    deep = await self.deep_dive_critical(critical_high, target_url, meta)
                result["deep_dive"] = deep
                if deep:
                    print_ok(f"    PoC generado para {len(deep)} hallazgos")
            else:
                print_info("    [3/3] Sin hallazgos CRITICAL/HIGH — deep dive omitido")

            stats = self.stats
            print_ok(
                f"    IA completada: {stats['calls']} llamadas | "
                f"{stats['tokens_used']:,} tokens ({stats['budget_pct']}% presupuesto)"
            )

        except Exception as e:
            print_err(f"    Error en IA (Rate limit / Conexión): {e}")

        return result

    # ── Backwards compatibility ─────────────────────────────────────────────
    async def batch_triage(
        self,
        vulns: list["Vuln"],
        target_url: str,
        max_vulns: int = 20,
        meta: dict = None,
    ) -> dict[str, dict]:
        """Compatibilidad con llamadas antiguas — usa mass_triage internamente."""
        return await self.mass_triage(vulns[:max_vulns], target_url, meta or {})

    async def generate_report_summary(
        self, target_url: str, vulns: list["Vuln"], meta: dict, duration: float
    ) -> str:
        """Compatibilidad con llamadas antiguas."""
        from utils.vuln import count_by_severity, risk_score
        counts       = count_by_severity(vulns)
        score, level = risk_score(counts)
        top_3   = [f"- [{v.severity}] {v.title}" for v in vulns[:3]]
        system  = "Eres un experto en ciberseguridad. Escribe en español. Sé conciso."
        user    = (
            f"Target: {target_url}\nRiesgo: {level} (score: {score})\n"
            f"Vulns: {counts}\nTop: {chr(10).join(top_3)}\n"
            "Escribe un resumen ejecutivo de 4-5 oraciones."
        )
        resp = await self._chat(system, user, max_tokens=400, temperature=0.3)
        return resp or ""

    async def suggest_advanced_tests(
        self, target_url: str, technologies: list[str],
        open_ports: list[dict], vulns_found: list["Vuln"]
    ) -> list[str]:
        """Compatibilidad con llamadas antiguas."""
        return []

    @property
    def stats(self) -> dict:
        return {
            "calls":       self._calls_made,
            "tokens_used": self._token_budget_used,
            "budget_pct":  round(self._token_budget_used / max(self.session_token_limit, 1) * 100, 1),
            "available":   self._available,
        }
