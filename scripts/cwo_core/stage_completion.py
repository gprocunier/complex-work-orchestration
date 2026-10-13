"""Closed-family consumption of controller-owned private stage proofs.
Not a proof issuer. A future controller must provide all original checked
receipts, private adjudication, applicable postimage and exact closure recipe.
Missing material is controlled non-readiness, never a worker acceptance flag.
Historical A3-L uses its original independently pinned reader separately.
"""
import copy,hashlib,json
from pathlib import Path
from . import stage_evidence as preflight
from .stage_evidence import exact
class CompletionError(ValueError):pass

def need(v,label):
    if v is not True:raise CompletionError(label)

def shape(v,keys,label):need(type(v) is dict and set(v)==set(keys),label)
def digest(v):need(type(v) is str and len(v)==64 and all(c in '0123456789abcdef' for c in v),'completion-digest');return v
def canonical(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def _consume(binding,registry,unit,row):
    before=canonical(binding.data);row_before=canonical(row)
    shape(row,{'owner','slot','role','obligations','proof_path','proof_sha256'},'completion-row')
    need(type(unit) is str and bool(unit),'completion-unit')
    need(registry.completion_reader_key(row['owner'],row['slot'],row['role'])=='independent-native-stage-proof:v1','completion-generic-recipe-family')
    need((row['owner'],row['slot']) in registry.consumed,'completion-original-consumed-pair')
    path=binding.data.get('economic_completion_recipe_path')
    bundle=preflight.read(binding,path)
    shape(bundle,{'kind','recipes'},'completion-recipe-bundle')
    need(bundle['kind']=='controller-closed-family-completion-recipes:v1' and type(bundle['recipes']) is dict and unit in bundle['recipes'],'completion-recipe-unavailable')
    recipe=bundle['recipes'][unit]
    shape(recipe,{'unit','owner','slot','role','obligations','proof_path','bead_id','segment_id',
                  'write_paths','validation_specs','baseline_files','transaction_id','plan_sha256','closed_bead_projection_sha256'},'completion-recipe')
    need(all(exact(recipe[k],row[k]) for k in ('owner','slot','role','obligations','proof_path')) and recipe['unit']==unit,'completion-recipe-identity')
    need(type(recipe['write_paths']) is list and all(type(p) is str and p and not Path(p).is_absolute() and '..' not in Path(p).parts for p in recipe['write_paths']) and len(set(recipe['write_paths']))==len(recipe['write_paths']),'completion-write-scope')
    if row['role']=='review':need(recipe['write_paths']==[],'completion-review-mutation-permission')
    need(type(recipe['bead_id']) is str and bool(recipe['bead_id']),'completion-bead')
    need(type(recipe['segment_id']) is str and bool(recipe['segment_id']) and type(recipe['transaction_id']) is str and bool(recipe['transaction_id']),'completion-operation-identity')
    digest(recipe['plan_sha256']);digest(recipe['closed_bead_projection_sha256'])
    need(type(recipe['baseline_files']) is dict and bool(recipe['baseline_files']),'completion-baseline-map')
    need(type(recipe['validation_specs']) is dict and bool(recipe['validation_specs']),'completion-mandatory-validation-map')
    digest(row['proof_sha256'])
    need(binding.data['files'].get(row['proof_path'])==row['proof_sha256'],'completion-original-proof-pin')
    proof=preflight.read(binding,row['proof_path'])
    fields={'kind','unit','owner','slot','role','decision','full_route_accepted','transaction_result_path',
            'containment_path','adjudication_path','validation_receipts','postimage','bead_id'}
    shape(proof,fields,'completion-proof-shape')
    need(proof['kind']=='controller-private-native-stage-proof:v1'
         and proof['decision']=='accepted-private-stage-only' and proof['full_route_accepted'] is False
         and all(exact(proof[k],recipe[k]) for k in ('unit','owner','slot','role','bead_id')),'completion-private-decision')
    result=preflight.read(binding,proof['transaction_result_path'])
    need(result.get('accepted') is True and result.get('state')=='ACCEPTED'
         and result.get('transaction_id')==recipe['transaction_id']
         and result.get('plan_sha256')==recipe['plan_sha256'],'completion-final-transaction')
    # The current product ACCEPTED boolean is not enough: consume independent
    # scope/test adjudication and exact owned closure before considering it.
    closure=preflight.read(binding,proof['containment_path'])
    shape(closure,{'kind','transaction_id','bead_id','all_contained','supervisor_closed',
                   'diagnostic_pending','original_physical_proof_paths'},'completion-closure-shape')
    need(closure['kind']=='controller-observed-native-stage-closure:v1'
         and closure['transaction_id']==recipe['transaction_id'] and closure['bead_id']==recipe['bead_id']
         and closure['all_contained'] is True and closure['supervisor_closed'] is True
         and type(closure['diagnostic_pending']) is int and closure['diagnostic_pending']==0,'completion-owned-closure')
    physical=closure['original_physical_proof_paths']
    need(type(physical) is list and bool(physical) and all(type(p) is str and bool(p) for p in physical)
         and len(set(physical))==len(physical),'completion-physical-proof-map')
    # Original observations are pinned and required, not reconstructed from
    # absent processes. Their contract-specific adjudication is independently
    # frozen in the private controller decision below, not inferred here.
    for path in physical:
        observed=preflight.read(binding,path)
        need(observed.get('all_contained') is True and observed.get('transaction_id')==recipe['transaction_id'],'completion-original-physical-observation')
    adjudication=preflight.read(binding,proof['adjudication_path'])
    shape(adjudication,{'kind','unit','owner','slot','role','decision','full_route_accepted',
        'transaction_result_sha256','containment_sha256','physical_proof_pins',
        'obligations','scope_verified','validation_verified','closure_verified','baseline_verified'},'completion-adjudication-shape')
    need(adjudication['kind']=='controller-sol-private-stage-adjudication:v1'
        and adjudication['decision']=='accepted-private-stage-only' and adjudication['full_route_accepted'] is False
        and all(exact(adjudication[k],recipe[k]) for k in ('unit','owner','slot','role','obligations'))
        and all(adjudication[k] is True for k in ('scope_verified','validation_verified','closure_verified','baseline_verified')),'completion-independent-adjudication')
    need(adjudication['transaction_result_sha256']==binding.data['files'][proof['transaction_result_path']]
         and adjudication['containment_sha256']==binding.data['files'][proof['containment_path']]
         and exact(adjudication['physical_proof_pins'],{p:binding.data['files'][p] for p in physical}),'completion-adjudicated-original-joins')
    receipts=proof['validation_receipts']
    need(type(receipts) is dict and set(receipts)==set(recipe['validation_specs']),'completion-required-validation-set')
    import cwo_core.checked_command as checked_command
    preflight.pinned(binding,str(Path(checked_command.__file__).resolve()))
    normalize_command_spec=checked_command.normalize_command_spec
    for name,spec_path in recipe['validation_specs'].items():
        need(type(name) is str and bool(name),'completion-check-id')
        spec=preflight.read(binding,spec_path);need(type(spec.get('version')) is int,'completion-spec-type')
        normalized=normalize_command_spec(spec)
        receipt=preflight.read(binding,receipts[name])
        need(receipt.get('result_type')=='cwo-checked-command-result' and type(receipt.get('version')) is int and receipt['version']==1
            and receipt.get('command_id')==normalized['command_id'] and receipt.get('spec_sha256')==canonical(normalized)
            and receipt.get('execution_status')=='passed' and receipt.get('preflight_status')=='passed'
            and receipt.get('execution_started') is True and type(receipt.get('exit_code')) is int and receipt['exit_code']==0
            and receipt.get('hash_match') is True and receipt.get('quarantine_required') is False,'completion-checked-validation')
        if normalized['mode']!='argv':
            expected=hashlib.sha256(normalized['source'].encode()).hexdigest()
            need(receipt.get('linted_sha256')==expected and receipt.get('executed_sha256')==expected,'completion-execution-hash')
    post=proof['postimage'];need(type(post) is dict and set(post)<=set(recipe['write_paths']),'completion-postimage-scope')
    for logical,value in post.items():
        shape(value,{'path','sha256'},'completion-postimage-record');digest(value['sha256'])
        need(binding.data['files'].get(value['path'])==value['sha256'],'completion-postimage-pin')
        preflight.pinned(binding,value['path'])
    for path,h in recipe['baseline_files'].items():
        digest(h);need(binding.data['files'].get(path)==h,'completion-current-baseline-pin');preflight.pinned(binding,path)
    admission_boundary = binding.admission_boundary
    preflight.pinned(binding,str(Path(admission_boundary.__file__).resolve()))
    registry.guard()
    show=admission_boundary.show
    issue=show(binding.root,Path(binding.data['database']),recipe['bead_id'])
    need(type(issue) is dict and issue.get('status')=='closed' and issue.get('assignee') in (None,''),'completion-owned-bead-not-closed')
    import cwo_core.native_pool_transaction as transaction
    preflight.pinned(binding,str(Path(transaction.__file__).resolve()))
    need(transaction.execution_authoritative_bead_sha256(issue)==recipe['closed_bead_projection_sha256'],'completion-final-bead-scope-drift')
    # Every exact input and supplied binding is rechecked after external readers.
    for path,h in binding.data['files'].items():preflight.pinned(binding,path)
    need(canonical(binding.data)==before and canonical(row)==row_before,'completion-reentrant-drift')
    return True

def consume(binding,registry,unit,row):
    try:
        # The current controller holds its owner/state exclusion across final
        # observation and the caller's terminal commit. All external observers
        # precede the final Bead snapshot and deterministic file checks.
        with binding.exclusion:
            return _consume(binding,registry,unit,row)
    except CompletionError:raise
    except (OSError,RuntimeError,ValueError,TypeError,KeyError,AttributeError) as error:
        raise CompletionError('completion-material-or-reader-unavailable') from error
