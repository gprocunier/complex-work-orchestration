"""Tests resolve predetermined operator grants without touching host configuration."""

from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from cwo_core import outbound_approval
from cwo_core.lead_authority import AuthorityError
from cwo_core.policy import executor_config

REFERENCE = "abcde" * 12 + "abcd"


def outbound_grant(bead_id, epic_id, executor, maximum_share_boundary="patch-branch", *, project=None):
    return {
        "project": str(project or Path(__file__).resolve().parents[1]), "bead_id": bead_id, "epic_id": epic_id,
        "executor": executor, "provider_key": executor_config(executor)["provider_key"],
        "maximum_share_boundary": maximum_share_boundary,
    }


@contextmanager
def approved_outbound(*grants):
    by_reference = {REFERENCE: grants[0], **{"0" * 63 + str(i): value for i, value in enumerate(grants[1:], 1)}}

    def resolve(operation, reference):
        if operation != outbound_approval.OUTBOUND_APPROVAL or reference not in by_reference:
            raise AuthorityError("test grant was not published")
        return by_reference[reference]

    with patch.object(outbound_approval, "configured_approval", side_effect=resolve) as approval:
        yield approval
