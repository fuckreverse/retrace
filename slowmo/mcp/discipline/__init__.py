"""
Discipline Injection — prevents LLM drift during long analysis sessions.

Periodically reinjects analysis rules and constraints into tool responses
to keep the AI on track. Based on algokiller-plugin's discipline system.
"""

from .injector import DisciplineInjector

__all__ = ["DisciplineInjector"]
