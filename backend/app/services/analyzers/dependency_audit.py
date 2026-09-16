from app.services.analyzers.base import Analyzer, AnalyzerContext, AnalyzerFinding


class DependencyAuditAnalyzer(Analyzer):
    name = "dependency_audit"

    def run(self, ctx: AnalyzerContext) -> list[AnalyzerFinding]:
        # TODO: discover manifests (requirements*.txt, pyproject.toml, package-lock.json).
        #       Python: `pip-audit -r <file> --no-deps --disable-pip -f json` via
        #       run_in_sandbox. Never let pip-audit install/build packages: sdists run setup.py.
        #       JS: lockfile-based audit (e.g. OSV) with no `npm install` on user code.
        raise NotImplementedError
