from typing import ParamSpec, Any


EmailVerificationInfo = tuple[str, str]
Params = ParamSpec('Params')
DetailedMessage = list[dict[str, Any] | None]


