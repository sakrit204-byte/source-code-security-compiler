"""Compiler-based source code security scanner for C."""

from .pipeline import VERSION, run_pipeline

__all__ = ["run_pipeline", "VERSION"]
