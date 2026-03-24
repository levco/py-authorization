# py-authorization

A policy-based authorization library for Python + SQLAlchemy. Define declarative policies with strategies that control access to entities and queries.

## Install

```bash
pip install py-authorization
```

### uv

In your `pyproject.toml` dependencies:

```toml
dependencies = [
  "py-authorization<2.1.0,>=2.0.0",
]
```

To override with a git branch, tag, commit during development, add a `[tool.uv.sources]` section:

```toml
# Git branch (for CI or teammate testing before a release)
[tool.uv.sources]
py-authorization = { git = "ssh://git@github.com/levco/py-authorization.git", branch = "or-strategy" }

# Specific tag
[tool.uv.sources]
py-authorization = { git = "ssh://git@github.com/levco/py-authorization.git", tag = "2.0.0" }

# Specific commit
[tool.uv.sources]
py-authorization = { git = "ssh://git@github.com/levco/py-authorization.git", rev = "abc1234" }
```

Then run `uv sync` to install.

## Quick start

```python
from py_authorization import Authorization, Policy, Strategy, PolicyStrategy, Context, User

# 1. Define strategies
class TeamMemberStrategy(PolicyStrategy):
    def apply_policies_to_entity(self, entity, context):
        return entity if context.user.id in entity.team_ids else None

    def apply_policies_to_query(self, query, context):
        return query.filter(Model.team_ids.contains(context.user.id))

# 2. Define policies
policies = [
    Policy(
        name="Admin full access",
        resources=["*"],
        roles=["admin"],
        actions=["*"],
    ),
    Policy(
        name="Team members can read projects",
        resources=["Project"],
        roles=["member"],
        actions=["read"],
        strategies=[Strategy("TeamMemberStrategy")],
    ),
]

# 3. Create authorization instance
auth = Authorization(
    policies=policies,
    strategy_mapper_callable=lambda: {"TeamMemberStrategy": TeamMemberStrategy},
)

# 4. Check access
user = User(role="member", id=42)
auth.is_allowed(user=user, action="read", resource="Project")
auth.apply_policies_to_one(user=user, entity=project, action="read")
auth.apply_policies_to_query(user=user, query=query, action="read")
```

## Core concepts

### Policy

A `Policy` matches requests by resource, role, and action, then delegates to strategies for fine-grained filtering.

```python
@dataclass
class Policy:
    name: str
    resources: list[str]       # Resource names or ["*"] for all
    roles: list[str]           # Role names or ["*"] for all
    actions: list[str]         # Action names or ["*"] for all
    sub_action: str | None     # Optional sub-action filter
    strategies: list[Strategy] | None      # AND chain — all must pass
    or_strategies: list[Strategy] | None   # OR chain — any one passing grants access
    deny: bool                 # Explicit deny (takes precedence)
    last_rule: bool            # Stop matching after this policy's resources
```

### Strategy

A `Strategy` is a named reference to a `PolicyStrategy` implementation, resolved at runtime via the strategy mapper.

### PolicyStrategy

Base class for strategy implementations. Override one or both methods:

```python
class MyStrategy(PolicyStrategy):
    def apply_policies_to_entity(self, entity, context):
        """Return entity if allowed, None if denied."""
        ...

    def apply_policies_to_query(self, query, context):
        """Return filtered query."""
        ...
```

## `or_strategies` (v2.0.0)

Policies can declare `or_strategies` alongside `strategies` for mixed AND+OR semantics:

```python
Policy(
    name="Read deals via membership, shared vault, or public link",
    resources=["Deal"],
    roles=["borrower", "guest", "public_vault_viewer"],
    actions=["read"],
    strategies=[Strategy("VisibilityStrategy")],          # AND — must pass
    or_strategies=[
        Strategy("UserOnDealStrategy"),                    # OR \
        Strategy("SharedVaultStrategy"),                   # OR  } any one = access
        Strategy("PublicVaultViewerStrategy"),              # OR /
    ],
)
```

**Semantics:**

| `strategies` | `or_strategies` | Result |
|---|---|---|
| not set | not set | Allow (no filtering) |
| set | not set | All must pass (AND) |
| not set | set | Any one must pass (OR) |
| set | set | AND must pass **and** at least one OR must pass |

**Query-level OR** combines each strategy's result via PK subqueries (not `Query.union()`) for SQLAlchemy 1.4 compatibility:

```sql
WHERE visibility_check
  AND (
    id IN (SELECT id FROM ... WHERE /* UserOnDeal */)
    OR id IN (SELECT id FROM ... WHERE /* SharedVault */)
    OR id IN (SELECT id FROM ... WHERE /* PublicVaultViewer */)
  )
```

## API

| Method | Description |
|---|---|
| `is_allowed(user, action, resource)` | Boolean permission check (no entity) |
| `is_entity_allowed(user, action, entity, resource)` | Check a specific entity |
| `apply_policies_to_one(user, entity, action)` | Returns entity if allowed, `None` if denied |
| `apply_policies_to_many(user, entities, action)` | Filters a list of entities |
| `apply_policies_to_query(user, query, action)` | Applies strategy filters to a SQLAlchemy query |
| `get_permissions_info(user, action, resource)` | Returns `CheckResponse` with permission info for frontend |

## Development

```bash
pip install -e .
pip install assertpy pytest

pytest tests/ -v
```

## Releasing

1. Update `__version__` in `py_authorization/__init__.py`
2. Commit, tag, and push:
   ```bash
   git tag 2.0.0
   git push origin main --tags
   ```
3. Consumers pin to the tag:
   ```toml
   [tool.uv.sources]
   py-authorization = { git = "ssh://git@github.com/levco/py-authorization.git", tag = "2.0.0" }
   ```
4. Or use version constraints:
   ```toml
   "py-authorization<2.1.0,>=2.0.0"
   ```
