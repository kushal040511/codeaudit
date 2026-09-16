from pathlib import Path

import networkx as nx

from app.services.graph.parser import ParsedModule


def build_dependency_graph(modules: list[ParsedModule], root: Path) -> nx.DiGraph:
    """Build a module-level import graph (nodes = modules, edges = imports).

    TODO: resolve relative/absolute imports against `root`, mark external deps.
    """
    raise NotImplementedError


def graph_metrics(graph: nx.DiGraph) -> dict[str, float]:
    """Architectural metrics: cycles, fan-in/fan-out, coupling, depth, etc.

    TODO: implement (nx.simple_cycles, degree centrality, ...).
    """
    raise NotImplementedError
