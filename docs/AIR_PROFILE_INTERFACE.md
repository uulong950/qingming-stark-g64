# AIR Profile Interface

Each compiled AIR profile supplies:

```text
air_id
public input layout
trace generator
constraint evaluator
quotient evaluator
local verifier checks
```

Current profile:

```text
QINGMING-AIR-GEOCLOCK-G64

public_inputs[0] = transition_ratio

constraint:
  trace_next - transition_ratio * trace_current = 0
```

New business logic should be added as a compiled AIR profile, not as a black-box runtime program.
