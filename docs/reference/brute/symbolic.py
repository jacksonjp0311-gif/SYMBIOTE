"""Finite-state *symbolic support* inference with no full-machine enumeration.

Each partial hypothesis is an accessible deterministic Moore-machine prefix,
canonically named by state first-visit order. Unvisited states and transition
entries remain existentially unspecified. This represents *all possible*
completions with at most `max_states` hidden states, without enumerating their
labelled complete tables. No posterior probabilities or unconditional proof of
model adequacy are implied.

Strict work budgets fail closed: evidence is durably recorded even when a
prediction cannot be computed, and the user may replay at a higher budget.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

ALL=0b1111
TRANS_UNKNOWN=-1


def mask_for_observation(obs):
    if len(obs)!=2 or any(x not in (0,1,None) for x in obs):
        raise ValueError('expected two nullable binary channels')
    mask=0
    for c in range(4):
        if all(value is None or ((c>>(1-j))&1)==value for j,value in enumerate(obs)):
            mask |= 1<<c
    return mask


@dataclass(frozen=True, slots=True)
class Prefix:
    trans:tuple[int,...]
    masks:tuple[int,...]
    current:int
    used:int


class BudgetExceeded(RuntimeError): pass
class GrammarContradiction(RuntimeError): pass


class SymbolicLearner:
    """Exact support on the explored action/observation trace, within `max_states`.

    Neither true n nor true hidden coordinates are inputs. If the finite
    state-count assumption is wrong, a seemingly unanimous conditional support
    can still be wrong in the physical environment. NEVER issue unconditional
    guarantees from these hypotheses alone.
    """
    def __init__(self,max_states=4,max_prefixes=160000):
        if not 1<=max_states<=6:raise ValueError('maximum state count must be 1..6')
        if max_prefixes<4:raise ValueError('need at least four hypothesis rows')
        self.max_states=max_states
        self.max_prefixes=max_prefixes
        self.evidence=[]
        self.belief=frozenset()
        self.status='uninitialized'
        self.transitions_examined=0
        self.max_rows_seen=0
        self.last_failure=None

    @property
    def count(self):return len(self.belief)

    def initialize(self,obs):
        if self.evidence:raise ValueError('already initialized')
        mask=mask_for_observation(obs)
        trans=(TRANS_UNKNOWN,)*(self.max_states*2)
        emission=(mask,)+(0,)*(self.max_states-1)
        self.belief=frozenset((Prefix(trans,emission,0,1),))
        self.status='supported'
        self.evidence.append((None,tuple(obs)))
        self.max_rows_seen=1

    def successors(self,prefix:Prefix,action:int,observed_mask:int=ALL):
        edge=prefix.current*2+action
        known=prefix.trans[edge]
        if known>=0:
            choices=(known,)
        else:
            choices=range(prefix.used+int(prefix.used<self.max_states))
        for dest in choices:
            new=dest==prefix.used
            prior=ALL if new else prefix.masks[dest]
            emission=prior&observed_mask
            if not emission:continue
            nt=prefix.trans
            if known<0:
                newt=list(nt);newt[edge]=dest;nt=tuple(newt)
            nm=prefix.masks
            if new or emission!=prior:
                newm=list(nm);newm[dest]=emission;nm=tuple(newm)
            yield Prefix(nt,nm,dest,prefix.used+int(new))

    def predict_support(self,action:int):
        if action not in (0,1):raise ValueError('action must be 0 or 1')
        if self.status!='supported':return None
        union=0
        for p in self.belief:
            edge=p.current*2+action
            dst=p.trans[edge]
            if dst<0:
                for j in range(p.used):union |= p.masks[j]
                if p.used<self.max_states:union |= ALL
            else:union |= p.masks[dst]
            if union==ALL:break
        return tuple(c for c in range(4) if union&(1<<c))

    def conditional_certificate(self,action:int):
        support=self.predict_support(action)
        return support[0] if support is not None and len(support)==1 else None

    def observe(self,action:int,obs):
        if not self.evidence:raise ValueError('not initialized')
        if action not in (0,1):raise ValueError('action must be 0 or 1')
        mask=mask_for_observation(obs)
        self.evidence.append((action,tuple(obs)))
        if self.status!='supported':
            # Do not silently lose evidence. A later retry reconstructs from
            # all previously recorded observations, including this one.
            return
        try:self._update(action,mask)
        except BudgetExceeded as exc:
            self.status='budget_exhausted'
            self.last_failure=str(exc)
            self.belief=frozenset()  # cannot use partial row set
        except GrammarContradiction as exc:
            self.status='grammar_contradicted'
            self.last_failure=str(exc)
            self.belief=frozenset()

    def _update(self,action,mask):
        result=set()
        for p in self.belief:
            for candidate in self.successors(p,action,mask):
                self.transitions_examined+=1
                result.add(candidate)
                if len(result)>self.max_prefixes:
                    raise BudgetExceeded('unambiguous work cap hit; abstain and preserve evidence')
        if not result:
            raise GrammarContradiction('no finite model under state cap explains all observations')
        self.max_rows_seen=max(self.max_rows_seen,len(result))
        self.belief=frozenset(result)

    def reconstruct(self,max_states=None,max_prefixes=None):
        """Transactional, explicit hypothesis expansion; no forgotten evidence."""
        new=SymbolicLearner(max_states or self.max_states,max_prefixes or self.max_prefixes)
        if not self.evidence:raise ValueError('not initialized')
        initial=self.evidence[0][1]
        new.initialize(initial)
        for a,obs in self.evidence[1:]:new.observe(a,obs)
        return new

    def snapshot(self):
        return {'status':self.status,'conditional_model_scope':f'deterministic <= {self.max_states} hidden states',
                'model_rows':self.count,'evidence_count':len(self.evidence),
                'max_rows_seen':self.max_rows_seen,'transitions_examined':self.transitions_examined,
                'last_failure':self.last_failure,'physical_certificate_authorized':False}
