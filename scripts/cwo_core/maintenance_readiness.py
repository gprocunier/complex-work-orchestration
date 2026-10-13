"""Persist real precommit evidence without changing frozen execution scope.

This is an owner-controlled evidence producer, not an admission bypass. The
existing ready-set evaluator, exact Bead claim CAS and admitted launcher still
perform every downstream decision. Caller must serialize its mission-owned
leaf's metadata writes; the independently repeated actual show is authoritative.
"""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
from typing import Any,Callable,Mapping
from .maintenance_authority import require_maintenance_operation
from .native_pool_contracts import canonical_sha256,write_private_artifact
from .native_pool_transaction import execution_authoritative_bead_sha256
from .native_precommit import validate_precommit_receipt
from .work_sizing import build_policy_fit_commitment,build_worker_commitment_from_receipt,validate_worker_commitment

class MaintenanceReadinessError(ValueError):pass

def _need(ok:bool,name:str)->None:
 if ok is not True:raise MaintenanceReadinessError('maintenance-readiness-'+name)

def persist_precommit_readiness(*,operation,verifier,claim_adapter,work_plan,
 precommit_receipt,operative_routing,current_authority,evidence_dir:Path,
 persist_admission:Callable[[str,Mapping[str,Any],str],None])->dict[str,Any]:
 """Issue evidence from the genuine receipt and verify actual exact-scope readback.

 ``persist_admission(bead_id,new_admission,expected_whole_issue_sha256)`` is the
 trusted owner's single-writer backend, never worker-supplied. If it cannot
 preserve the expected state it must reject. No assumption of backend CAS is
 made: the independent scope/readback joins below remain required.
 """
 cap=require_maintenance_operation(operation,verifier=verifier)
 bound=cap.bound_plan();children=bound.get('children')
 _need(type(children) is list and len(children)==1,'single-child-required')
 child=children[0];bead_id=child['bead_id']
 _need(type(work_plan) is dict and work_plan.get('bead_id')==bead_id
  and canonical_sha256(work_plan)==child['work_plan_sha256'],'estimate-binding-mismatch')
 errors=validate_precommit_receipt(precommit_receipt,work_plan,operative_routing=operative_routing,
  live=True,require_accepting=True,current_authority=current_authority)
 _need(errors==[],'precommit-invalid:'+ ';'.join(errors))
 policy_receipt=(work_plan.get('fit_mode')=='deterministic'
  and precommit_receipt.get('submission_id')=='deterministic-policy'
  and precommit_receipt.get('requested_model')=='gpt-5.3-codex-spark')
 commitment=(build_policy_fit_commitment(work_plan,precommit_receipt=precommit_receipt,current_authority=current_authority)
  if policy_receipt else build_worker_commitment_from_receipt(work_plan,precommit_receipt,current_authority=current_authority))
 errors=validate_worker_commitment(commitment,work_plan,precommit_receipt=precommit_receipt,current_authority=current_authority)
 _need(errors==[],'commitment-invalid:'+ ';'.join(errors))
 before=deepcopy(dict(claim_adapter.show_exact(bead_id)))
 _need(execution_authoritative_bead_sha256(before)==child['bead_projection_sha256'],'pre-scope-drift')
 _need(before.get('status')=='open' and not before.get('assignee'),'leaf-not-unclaimed')
 metadata=before.get('metadata');_need(type(metadata) is dict,'metadata-invalid')
 admission=metadata.get('cwo_ready_set_admission')
 if type(admission) is str:
  import json
  admission=json.loads(admission)
 _need(type(admission) is dict and canonical_sha256(admission.get('work_plan'))==canonical_sha256(work_plan),'seeded-plan-mismatch')
 updated=deepcopy(admission);updated.update(precommit_receipt=deepcopy(precommit_receipt),worker_commitment=commitment)
 for key in ('precommit_receipt','worker_commitment'):
  _need(key not in admission or canonical_sha256(admission[key])==canonical_sha256(updated[key]),'evidence-slot-already-filled')
 intent={'kind':'cwo-maintenance-readiness-intent','version':1,'operation_sha256':cap.operation_sha256,
  'bead_id':bead_id,'before_issue_sha256':canonical_sha256(before),
  'before_execution_sha256':execution_authoritative_bead_sha256(before),
  'admission_sha256':canonical_sha256(updated),'precommit_receipt_sha256':precommit_receipt['receipt_sha256']}
 path=evidence_dir/'readiness-intent.json';_need(not path.exists(),'intent-replayed')
 write_private_artifact(path,intent)
 cap.revalidate()
 # Observe again BEFORE trigger, as well as after. Single-writer ownership and
 # this check prevent stale caller snapshots from overwriting known new state.
 _need(canonical_sha256(dict(claim_adapter.show_exact(bead_id)))==canonical_sha256(before),'pre-write-drift')
 cap.revalidate()  # Observer may synchronously revoke while returning unchanged data.
 persist_admission(bead_id,updated,intent['before_issue_sha256'])
 cap.revalidate()
 after=deepcopy(dict(claim_adapter.show_exact(bead_id)))
 _need(execution_authoritative_bead_sha256(after)==child['bead_projection_sha256'],'post-scope-drift')
 expected=deepcopy(metadata);expected['cwo_ready_set_admission']=updated
 _need(canonical_sha256(after.get('metadata'))==canonical_sha256(expected),'exact-metadata-readback-mismatch')
 for key in set(before)|set(after):
  if key not in {'metadata','updated_at','revision'}:
   _need(canonical_sha256(after.get(key))==canonical_sha256(before.get(key)),'unrelated-field-drift:'+key)
 receipt={'kind':'cwo-maintenance-readiness-persisted','version':1,'intent_sha256':canonical_sha256(intent),
  'before_issue_sha256':canonical_sha256(before),'after_issue_sha256':canonical_sha256(after),
  'execution_projection_unchanged':True,'bead_id':bead_id,'admission_sha256':canonical_sha256(updated)}
 write_private_artifact(evidence_dir/'readiness-persisted.json',receipt)
 return after
