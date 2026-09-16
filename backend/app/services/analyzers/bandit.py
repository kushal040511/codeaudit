from app.services.analyzers.base import Analyzer, AnalyzerContext, AnalyzerFinding


class BanditAnalyzer(Analyzer):
    name = "bandit"

    def run(self, ctx: AnalyzerContext) -> list[AnalyzerFinding]:
        # TODO: `bandit -r /src -f json` via run_in_sandbox, map -> AnalyzerFinding.
        raise NotImplementedError
