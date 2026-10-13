"""Explicit v2 maintenance releases; ordinary v1 release authority is unchanged."""
from __future__ import annotations
from copy import deepcopy
import datetime as dt
from pathlib import Path
from typing import Any,Mapping
from .maintenance_authority import require_maintenance_operation
from .maintenance_qualification import VerifiedMaintenanceQualification, require_maintenance_qualification
from .native_pool_contracts import canonical_sha256
from .native_precommit import validate_precommit_receipt
from .operative_routing import validate_operative_route_for_model
from .work_sizing import is_read_only_work_estimate

FIELDS={'evidence_type','version','schema','evidence_id','release_state','authority',
 'authority_bead','adjudication_bead','packet_id','attempt_nonce','requested_model',
 'work_plan_sha256','operative_routing_sha256','fit_prompt_sha256','precommit_receipt_sha256',
 'canary_receipt_sha256','adjudication_sha256','operation_class','authorized_operations',
 'workdir','repository_work_authorized','source_mutation_authorized','issued_at','expires_at',
 'release_requires','evidence_sha256','mission_id','operation_sha256','plan_sha256','role'}
OPERATIONS=['dispatchable-packet-validation','operative-prompt-render','supervision-start','supervision-arm','native-dispatch']
SCHEMA='schemas/native-release-evidence-v2.schema.json'

class MaintenanceReleaseError(ValueError):pass

def need(v,label):
 if v is not True:raise MaintenanceReleaseError('maintenance-release-'+label)

def seal(value):return canonical_sha256({k:v for k,v in value.items() if k!='evidence_sha256'})

def build_maintenance_release_evidence(*,candidate_packet:Mapping[str,Any],
 qualification:VerifiedMaintenanceQualification,current_authority:Mapping[str,Any],
 maintenance_operation,maintenance_verifier,now:dt.datetime|None=None,ttl_seconds:int=900):
 cap=require_maintenance_operation(maintenance_operation,verifier=maintenance_verifier)
 scope=cap.evidence()['operation'];bound=cap.bound_plan();packet=deepcopy(dict(candidate_packet))
 need(packet.get('stage')=='precommit-validated' and packet.get('operative_dispatch_authorized') is False,'candidate-stage-invalid')
 plan=packet.get('work_plan');precommit=packet.get('precommit_receipt');route=packet.get('operative_routing')
 need(type(plan) is dict and type(precommit) is dict and type(route) is dict,'candidate-material-missing')
 need(packet.get('requested_model')==scope['model'] and plan.get('write_paths')==scope['write_paths']
      and packet.get('scope',{}).get('workdir')==scope['workspace'],'scope-binding-mismatch')
 qualification=require_maintenance_qualification(qualification,operation=cap,verifier=maintenance_verifier)
 record=dict(qualification.record)
 need(record.get('model')==scope['model'],'qualification-model-mismatch')
 need(record.get('tool_profile_sha256')==canonical_sha256(packet.get('tool_policy',{}).get('permitted_tools')),'qualification-profile-mismatch')
 need(record.get('control_image_sha256')==bound.get('controller_overlay_sha256'),'qualification-image-mismatch')
 need(type(bound.get('children')) is list and len(bound['children'])==1 and bound['children'][0].get('bead_id')==plan.get('bead_id'),'bead-binding-mismatch')
 budget=current_authority.get('fit_inputs',{}).get('aggregate_budget')
 need(type(budget) is dict and budget.get('mode')=='maintenance-unbounded' and route.get('aggregate_budget')==budget,'maintenance-route-budget-required')
 if type(budget) is dict:
  need(budget.get('mission_id')==scope['mission_id'] and budget.get('mission_sha256')==scope['mission_sha256']
    and budget.get('operation_id')==scope['operation_id'] and budget.get('reservation')==scope['reservation']
    and budget.get('cumulative_before')==bound['budget']['cumulative_before'] and budget.get('budget_reset_allowed') is False,'route-budget-binding-mismatch')
 selected=current_authority.get('qualifications',{}).get(scope['model'])
 need(selected==record,'qualification-authority-mismatch')
 current=now or dt.datetime.now(dt.timezone.utc)
 need(current.tzinfo is not None and type(ttl_seconds) is int and 1<=ttl_seconds<=900,'lifetime-invalid')
 expiry=dt.datetime.fromisoformat(record['origin_expires_at'])
 need(dt.datetime.fromisoformat(record['origin_issued_at'])<=current<expiry,'qualification-expired')
 errors=validate_precommit_receipt(precommit,plan,operative_routing=route,
     expected_packet_id=packet.get('packet_id'),live=True,require_accepting=True,current_authority=current_authority)
 need(errors==[],'precommit-invalid:'+ ';'.join(errors))
 errors=validate_operative_route_for_model(route,scope['model'],work_estimate=plan,
     now=current.isoformat(),current_authority=current_authority)
 need(errors==[],'route-invalid:'+ ';'.join(errors))
 readonly=scope['role']=='review'
 need(readonly==is_read_only_work_estimate(plan),'role-sizing-mismatch')
 need(precommit['receipt_sha256']==packet.get('precommit_receipt_sha256'),'precommit-packet-hash-mismatch')
 decision={'kind':'controller-maintenance-release-adjudication','operation_sha256':cap.operation_sha256,
   'packet_sha256':canonical_sha256(packet),'qualification_receipt_sha256':record['receipt_sha256'],
   'scope_verified':True,'precommit_verified':True,'route_verified':True}
 expires=min(expiry,current+dt.timedelta(seconds=ttl_seconds))
 evidence={'evidence_type':'cwo-native-release-evidence','version':2,'schema':SCHEMA,
  'evidence_id':'maintenance-release-'+scope['operation_id'],'release_state':'operative-authorized',
  'authority':'cwo-maintenance-controller','authority_bead':plan['bead_id'],
  'adjudication_bead':plan['bead_id'],'packet_id':packet['packet_id'],
  'attempt_nonce':precommit['attempt_nonce'],'requested_model':scope['model'],
  'work_plan_sha256':canonical_sha256(plan),'operative_routing_sha256':canonical_sha256(route),
  'fit_prompt_sha256':precommit['fit_prompt_sha256'],'precommit_receipt_sha256':precommit['receipt_sha256'],
  'canary_receipt_sha256':record['canary_sha256'],'adjudication_sha256':canonical_sha256(decision),
  'operation_class':'native-operative-release','authorized_operations':OPERATIONS,
  'workdir':scope['workspace'],'repository_work_authorized':True,'source_mutation_authorized':not readonly,
  'issued_at':current.isoformat(),'expires_at':expires.isoformat(),'release_requires':scope['mission_id'],
  'mission_id':scope['mission_id'],'operation_sha256':cap.operation_sha256,
  'plan_sha256':scope['plan_sha256'],'role':scope['role'],'evidence_sha256':''}
 evidence['evidence_sha256']=seal(evidence)
 errors=validate_maintenance_release_evidence(evidence,maintenance_operation=cap,
     maintenance_verifier=maintenance_verifier,now=current)
 need(errors==[],'constructed-evidence-invalid:'+ ';'.join(errors))
 return evidence

def validate_maintenance_release_evidence(value:Any,*,maintenance_operation=None,
 maintenance_verifier=None,operation=None,expected_packet_id=None,
 expected_work_plan_sha256=None,expected_precommit_receipt_sha256=None,
 now=None,live=True,historical_parse=False):
 try:
  need(type(value) is dict and set(value)==FIELDS,'fields-invalid')
  need(type(value['version']) is int and value['version']==2 and value['schema']==SCHEMA
    and value['evidence_type']=='cwo-native-release-evidence','header-invalid')
  need(value['authority']=='cwo-maintenance-controller' and value['release_state']=='operative-authorized'
    and value['operation_class']=='native-operative-release','authority-invalid')
  need(type(live) is bool and type(historical_parse) is bool,'mode-invalid')
  need(not historical_parse or (not live and operation is None),'historical-dispatch-forbidden')
  for field in ('evidence_id','authority_bead','adjudication_bead','packet_id','attempt_nonce','requested_model','workdir','release_requires','mission_id','role','issued_at','expires_at'):
   need(type(value[field]) is str and bool(value[field].strip()),'text-field-invalid:'+field)
  need(value['role'] in ('review','product') and type(value['source_mutation_authorized']) is bool
    and value['source_mutation_authorized']==(value['role']=='product')
    and value['repository_work_authorized'] is True,'effect-scope-invalid')
  for k in ('work_plan_sha256','operative_routing_sha256','fit_prompt_sha256',
            'precommit_receipt_sha256','canary_receipt_sha256','adjudication_sha256',
            'operation_sha256','plan_sha256','evidence_sha256'):
   need(type(value[k]) is str and len(value[k])==64 and all(c in '0123456789abcdef' for c in value[k]),'digest-invalid')
  need(value['evidence_sha256']==seal(value),'inner-hash-invalid')
  need(value['authorized_operations']==OPERATIONS,'operation-list-invalid')
  if operation is not None:need(operation in OPERATIONS,'operation-not-authorized')
  issued=dt.datetime.fromisoformat(value['issued_at']);expires=dt.datetime.fromisoformat(value['expires_at'])
  need(issued.tzinfo is not None and issued<expires<=issued+dt.timedelta(seconds=900),'expiry-invalid')
  if live:need(issued<=(now or dt.datetime.now(dt.timezone.utc))<expires,'evidence-not-live')
  for k,v in [('packet_id',expected_packet_id),('work_plan_sha256',expected_work_plan_sha256),
              ('precommit_receipt_sha256',expected_precommit_receipt_sha256)]:
   if v is not None:need(value[k]==v,'expected-binding-mismatch')
  if not historical_parse:
   cap=require_maintenance_operation(maintenance_operation,verifier=maintenance_verifier)
   scope=cap.evidence()['operation'];bound=cap.bound_plan()
   need(type(bound.get('children')) is list and len(bound['children'])==1 and value['authority_bead']==value['adjudication_bead']==bound['children'][0].get('bead_id'),'bead-binding-mismatch')
   need(value['mission_id']==scope['mission_id'] and value['operation_sha256']==cap.operation_sha256
    and value['plan_sha256']==scope['plan_sha256'] and value['requested_model']==scope['model']
    and value['workdir']==scope['workspace'] and value['role']==scope['role']
    and value['release_requires']==scope['mission_id'],'current-authority-binding-mismatch')
  return []
 except (ValueError,TypeError,KeyError,AttributeError,OverflowError) as e:return [str(e)]


def authorize_maintenance_packet(*,candidate_packet,qualification,current_authority,maintenance_operation,maintenance_verifier,now=None):
    """Release the actual precommit candidate through current owner authority."""
    evidence=build_maintenance_release_evidence(candidate_packet=candidate_packet,qualification=qualification,
        current_authority=current_authority,maintenance_operation=maintenance_operation,
        maintenance_verifier=maintenance_verifier,now=now)
    packet=deepcopy(candidate_packet)
    packet.update(stage='operative-authorized',operative_dispatch_authorized=True,
        release_requires=evidence['release_requires'],release_evidence=evidence,
        release_evidence_sha256=evidence['evidence_sha256'])
    from prepare_native_worker import validate_native_worker_packet
    errors=validate_native_worker_packet(packet,dispatchable=True,current_authority=current_authority,
        maintenance_operation=maintenance_operation,maintenance_verifier=maintenance_verifier)
    need(errors==[],'released-packet-invalid:'+ ';'.join(errors))
    return packet
