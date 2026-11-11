--------------------------- MODULE ArenaProtocol ---------------------------
(***************************************************************************)
(* The EL1 mmap/munmap fast-path arena protocol, at the granularity of the *)
(* host code in src/syscall/mem.c and the EL1 code in src/core/shim-mmap.c. *)
(*                                                                         *)
(* A page here stands for one 2 MiB materialization block. Each vCPU owns  *)
(* one arena control (its slot). A vCPU is in EL0, in the EL1 fast path,   *)
(* or in HVC running host code; Helpers are host threads with no vCPU that *)
(* fault guest memory in from the host side.                               *)
(*                                                                         *)
(* Atomic steps are sequentially consistent: the store-buffering handshake *)
(* between el1_gate_enter and mmap_fastpath_host_gate_close is checked by  *)
(* scripts/check-sb-handshake.py, not here.                                *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS V,          \* vCPU threads, one arena slot each
          Helpers,    \* host-only threads (no vCPU, no slot)
          NoOne,      \* lock owner when free
          NPages,     \* guest pages (2 MiB blocks)
          ArenaPages, \* pages per arena generation
          MaxGen,     \* generation bound for model checking
          PubRing,    \* mmap publication ring capacity
          RetRing,    \* munmap retire ring capacity
          FlushArenaOnReuse, \* a refill or rewind flushes the whole arena
          ModelTLB    \* track TLB entries (a much larger state space)

T == V \cup Helpers
P == 1..NPages
Range(b, n) == b..(b + n - 1)
Min(S) == CHOOSE x \in S : \A y \in S : x <= y

VARIABLES
    pc,      \* per-thread program counter
    op,      \* per-thread host operation in progress
    arg,     \* per-thread page argument
    lock,    \* mmap_lock owner
    gate,    \* shim PT gate counter
    gref,    \* thread holds a gate reference (closed it, not reopened)
    active,  \* retire.producer_active per slot
    ctl,     \* per-slot arena control
    pub,     \* per-slot mmap publication ring (pages)
    ret,     \* per-slot munmap retire ring
    regions, \* host region metadata (pages)
    pte,     \* pages with a valid stage-1 descriptor
    live,    \* ghost: pages the guest holds mapped
    claim,   \* materialization claims (pages)
    dead,    \* vCPUs reaped by exec
    err,     \* first violated fail-closed check, or "none"
    tl       \* TLB: per-vCPU current and stale entries, per-thread pending TLBI

vars == <<pc, op, arg, lock, gate, gref, active, ctl, pub, ret,
          regions, pte, live, claim, dead, err>>

NoCtl == [gen |-> 0, cgen |-> 0, en |-> FALSE, base |-> 0, lim |-> 0,
          cur |-> 0, mgen |-> 0, mlo |-> 0, mhi |-> 0]

Init ==
    /\ pc = [t \in T |-> IF t \in V THEN "el0" ELSE "idle"]
    /\ op = [t \in T |-> "none"]
    /\ arg = [t \in T |-> 0]
    /\ lock = NoOne
    /\ gate = 0
    /\ gref = [t \in T |-> FALSE]
    /\ active = [s \in V |-> FALSE]
    /\ ctl = [s \in V |-> NoCtl]
    /\ pub = [s \in V |-> <<>>]
    /\ ret = [s \in V |-> <<>>]
    /\ regions = {}
    /\ pte = {}
    /\ live = {}
    /\ claim = {}
    /\ dead = {}
    /\ err = "none"
    /\ tl = [valid |-> [v \in V |-> {}], stale |-> [v \in V |-> {}],
             pend |-> [t \in T |-> {}]]

Goto(t, s) == pc' = [pc EXCEPT ![t] = s]
Fail(msg) == err' = IF err = "none" THEN msg ELSE err

(***************************************************************************)
(* Guest actions at EL0.                                                   *)
(***************************************************************************)
Runnable(v) == pc[v] = "el0" /\ v \notin dead /\ err = "none"

GuestMmap(v) ==
    /\ Runnable(v)
    /\ Goto(v, "m_pre")
    /\ UNCHANGED <<op, arg, lock, gate, gref, active, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

GuestMunmap(v, p) ==
    /\ Runnable(v)
    /\ Goto(v, "u_pre")
    /\ arg' = [arg EXCEPT ![v] = p]
    /\ UNCHANGED <<op, lock, gate, gref, active, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

\* A touch of a page with no descriptor and no TLB entry faults into the host.
GuestTouch(v, p) ==
    /\ Runnable(v)
    /\ p \notin pte
    /\ p \notin tl.valid[v] \cup tl.stale[v]
    /\ Goto(v, "h_acq")
    /\ op' = [op EXCEPT ![v] = "fault"]
    /\ arg' = [arg EXCEPT ![v] = p]
    /\ UNCHANGED <<lock, gate, gref, active, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

\* mprotect, mremap, MAP_FIXED or sigaltstack over page p: the arenas whose
\* bounds cover p are revoked (mmap_fastpath_revoke_range_locked).
GuestRevoke(v, p) ==
    /\ Runnable(v)
    /\ Goto(v, "h_acq")
    /\ op' = [op EXCEPT ![v] = "revoke"]
    /\ arg' = [arg EXCEPT ![v] = p]
    /\ UNCHANGED <<lock, gate, gref, active, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

GuestFork(v) ==
    /\ Runnable(v)
    /\ Goto(v, "h_acq")
    /\ op' = [op EXCEPT ![v] = "fork"]
    /\ UNCHANGED <<arg, lock, gate, gref, active, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

\* de_thread: siblings are reaped at their next safe point, which is EL0 in
\* this model (the run loop resumes a vCPU stopped inside the EL1 window and
\* host operations run to completion).
GuestExec(v) ==
    /\ Runnable(v)
    /\ \A u \in V \ {v} : pc[u] = "el0"
    /\ dead' = V \ {v}
    /\ Goto(v, "h_acq")
    /\ op' = [op EXCEPT ![v] = "exec"]
    /\ UNCHANGED <<arg, lock, gate, gref, active, ctl, pub, ret,
                   regions, pte, live, claim, err>>

\* A helper copies into a guest buffer and faults the page in host-side.
HelperTouch(h, p) ==
    /\ pc[h] = "idle"
    /\ err = "none"
    /\ p \notin pte
    /\ Goto(h, "h_acq")
    /\ op' = [op EXCEPT ![h] = "fault"]
    /\ arg' = [arg EXCEPT ![h] = p]
    /\ UNCHANGED <<lock, gate, gref, active, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

(***************************************************************************)
(* EL1 fast paths.                                                         *)
(***************************************************************************)
Bail(v, o) ==
    /\ Goto(v, "h_acq")
    /\ op' = [op EXCEPT ![v] = o]

\* el1_gate_enter, first gate read.
EnterPre(v, next, fallback) ==
    /\ IF gate > 0
       THEN Bail(v, fallback)
       ELSE Goto(v, next) /\ UNCHANGED op
    /\ UNCHANGED <<arg, lock, gate, gref, active, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

\* el1_gate_enter, announce.
Announce(v, next) ==
    /\ active' = [active EXCEPT ![v] = TRUE]
    /\ Goto(v, next)
    /\ UNCHANGED <<op, arg, lock, gate, gref, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

\* el1_gate_enter, second gate read.
EnterCheck(v, next, fallback) ==
    /\ IF gate > 0
       THEN /\ active' = [active EXCEPT ![v] = FALSE]
            /\ Bail(v, fallback)
       ELSE /\ Goto(v, next)
            /\ UNCHANGED <<active, op>>
    /\ UNCHANGED <<arg, lock, gate, gref, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

LeaveBail(v, o) ==
    /\ active' = [active EXCEPT ![v] = FALSE]
    /\ Bail(v, o)

MPre(v)  == pc[v] = "m_pre"  /\ EnterPre(v, "m_annc", "mmap")
MAnnc(v) == pc[v] = "m_annc" /\ Announce(v, "m_chk")
MChk(v)  == pc[v] = "m_chk"  /\ EnterCheck(v, "m_body", "mmap")

\* el1_mmap past the gate.
MBody(v) ==
    /\ pc[v] = "m_body"
    /\ LET c == ctl[v] IN
       IF c.gen # c.cgen
       THEN /\ ctl' = [ctl EXCEPT ![v].cgen = c.gen]
            /\ LeaveBail(v, "mmap")
            /\ UNCHANGED <<arg, lock, gate, gref, pub, ret,
                           regions, pte, live, claim, dead, err>>
       ELSE IF ~c.en \/ c.cur >= c.lim
       THEN /\ LeaveBail(v, "mmap")
            /\ UNCHANGED <<arg, lock, gate, gref, ctl, pub, ret,
                           regions, pte, live, claim, dead, err>>
       ELSE IF Len(pub[v]) >= PubRing
       THEN /\ LeaveBail(v, "pubonly")
            /\ UNCHANGED <<arg, lock, gate, gref, ctl, pub, ret,
                           regions, pte, live, claim, dead, err>>
       ELSE /\ pub' = [pub EXCEPT ![v] = Append(@, c.cur)]
            /\ ctl' = [ctl EXCEPT ![v].cur = c.cur + 1]
            /\ live' = live \cup {c.cur}
            /\ IF c.cur \in live
               THEN Fail("EL1 mmap returned a live page")
               ELSE UNCHANGED err
            /\ active' = [active EXCEPT ![v] = FALSE]
            /\ Goto(v, "el0")
            /\ UNCHANGED <<op, arg, lock, gate, gref, ret,
                           regions, pte, claim, dead>>

UPre(v) ==
    /\ pc[v] = "u_pre"
    /\ IF Len(ret[v]) >= RetRing - 1
       THEN /\ Bail(v, "munmap")
            /\ UNCHANGED <<arg, lock, gate, gref, active, ctl, pub, ret,
                           regions, pte, live, claim, dead, err>>
       ELSE EnterPre(v, "u_annc", "munmap")

UAnnc(v) == pc[v] = "u_annc" /\ Announce(v, "u_chk")
UChk(v)  == pc[v] = "u_chk"  /\ EnterCheck(v, "u_body", "munmap")

Owners(p) == {s \in V : ctl[s].en /\ ctl[s].base <= p /\ p < ctl[s].cur}

\* el1_munmap past the gate: find the arena, clear what the materialized
\* envelope says may be present, publish the retirement.
UBody(v) ==
    /\ pc[v] = "u_body"
    /\ LET p == arg[v] IN
       IF Owners(p) = {}
       THEN /\ LeaveBail(v, "munmap")
            /\ UNCHANGED <<arg, lock, gate, gref, ctl, pub, ret,
                           regions, pte, live, claim, dead, err>>
       ELSE LET s == IF v \in Owners(p) THEN v ELSE CHOOSE o \in Owners(p) : TRUE
                c == ctl[s]
                walk == c.mgen = c.gen /\ c.mlo <= p /\ p < c.mhi
            IN /\ pte' = IF walk THEN pte \ {p} ELSE pte
               /\ ret' = [ret EXCEPT ![v] = Append(@, [p |-> p, g |-> c.gen, s |-> s])]
               /\ live' = live \ {p}
               /\ active' = [active EXCEPT ![v] = FALSE]
               /\ Goto(v, "el0")
               /\ UNCHANGED <<op, arg, lock, gate, gref, ctl, pub,
                              regions, claim, dead, err>>

(***************************************************************************)
(* Host: mmap_lock, the gate, and the drain.                               *)
(***************************************************************************)
PubPages == UNION {{pub[s][i] : i \in 1..Len(pub[s])} : s \in V}
RetEntries == UNION {{ret[s][i] : i \in 1..Len(ret[s])} : s \in V}
RetPages == {e.p : e \in RetEntries}
AllRetEmpty == \A s \in V : ret[s] = <<>>

BadPub == \E s \in V : \E i \in 1..Len(pub[s]) :
            ~(ctl[s].base <= pub[s][i] /\ pub[s][i] < ctl[s].lim)
BadRet == \E e \in RetEntries :
            \/ ctl[e.s].gen # e.g
            \/ e.p < ctl[e.s].base
            \/ e.p >= ctl[e.s].cur
RetUnderClaim == \E e \in RetEntries : e.p \in claim

DrainErr ==
    IF BadPub THEN "publication outside its arena"
    ELSE IF BadRet THEN "stale retire generation or range"
    ELSE IF RetUnderClaim THEN "retire under a materialization claim"
    ELSE "none"

DrainedRegions == (regions \cup PubPages) \ RetPages

\* mmap_fastpath_rewind_control_if_clean_locked for the caller's slot.
Rewound(t, rg, c) ==
    IF /\ t \in V
       /\ c[t].en
       /\ c[t].base < c[t].cur
       /\ Range(c[t].base, c[t].lim - c[t].base) \cap rg = {}
       /\ Range(c[t].base, c[t].lim - c[t].base) \cap pte = {}
    THEN [c EXCEPT ![t].cur = c[t].base, ![t].mgen = 0,
                   ![t].mlo = 0, ![t].mhi = 0]
    ELSE c

\* Envelope reset: a materialized marker with no present descriptor left.
EnvelopeReset(c) ==
    [s \in V |->
        IF c[s].en /\ c[s].base < c[s].cur
           /\ Range(c[s].base, c[s].cur - c[s].base) \cap pte = {}
        THEN [c[s] EXCEPT !.mgen = 0, !.mlo = 0, !.mhi = 0]
        ELSE c[s]]

\* mmap_fastpath_drain_locked, under mmap_lock with the gate closed.
Drain(t) ==
    /\ regions' = DrainedRegions
    /\ pub' = [s \in V |-> <<>>]
    /\ ret' = [s \in V |-> <<>>]
    /\ ctl' = EnvelopeReset(Rewound(t, DrainedRegions, ctl))
    /\ IF DrainErr # "none" THEN Fail(DrainErr) ELSE UNCHANGED err

HAcq(t) ==
    /\ pc[t] = "h_acq"
    /\ lock = NoOne
    /\ lock' = t
    /\ Goto(t, IF op[t] = "pubonly" THEN "p_body" ELSE "h_close")
    /\ UNCHANGED <<op, arg, gate, gref, active, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

\* mmap_fastpath_host_gate_close: only the 0 -> 1 closer waits.
HClose(t) ==
    /\ pc[t] = "h_close"
    /\ gate' = gate + 1
    /\ gref' = [gref EXCEPT ![t] = TRUE]
    /\ Goto(t, IF gate = 0 THEN "h_wait" ELSE "h_drain")
    /\ UNCHANGED <<op, arg, lock, active, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

HWait(t) ==
    /\ pc[t] = "h_wait"
    /\ \A s \in V : ~active[s]
    /\ Goto(t, "h_drain")
    /\ UNCHANGED <<op, arg, lock, gate, gref, active, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

HDrain(t) ==
    /\ pc[t] = "h_drain"
    /\ Drain(t)
    /\ Goto(t, "h_op")
    /\ UNCHANGED <<op, arg, lock, gate, gref, active, pte, live, claim, dead>>

\* mmap_fastpath_host_gate_open; a zero count is an exec-reset gate.
GateOpen(t) ==
    /\ gate' = IF gref[t] /\ gate > 0 THEN gate - 1 ELSE gate
    /\ gref' = [gref EXCEPT ![t] = FALSE]

\* mmap_lock_release. A vCPU reaches EL0 only in a later step (HRet): the
\* TLBI the host requested runs there, after other threads can take the lock.
HRel(t) ==
    /\ pc[t] = "h_rel"
    /\ GateOpen(t)
    /\ lock' = NoOne
    /\ Goto(t, IF t \in V THEN "h_ret" ELSE "idle")
    /\ op' = [op EXCEPT ![t] = "none"]
    /\ UNCHANGED <<arg, active, ctl, pub, ret, regions, pte, live, claim, dead, err>>

HRet(t) ==
    /\ pc[t] = "h_ret"
    /\ Goto(t, "el0")
    /\ UNCHANGED <<op, arg, lock, gate, gref, active, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

\* mmap_lock_cond_wait: reopen, sleep, then reacquire through h_acq.
HCondWait(t) ==
    /\ pc[t] = "h_cw"
    /\ GateOpen(t)
    /\ lock' = NoOne
    /\ Goto(t, "h_sleep")
    /\ UNCHANGED <<op, arg, active, ctl, pub, ret, regions, pte, live, claim, dead, err>>

HSleep(t) ==
    /\ pc[t] = "h_sleep"
    /\ IF op[t] \in {"fork", "exec"} THEN claim = {} ELSE arg[t] \notin claim
    /\ Goto(t, "h_acq")
    /\ UNCHANGED <<op, arg, lock, gate, gref, active, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

(***************************************************************************)
(* Host operations, run with mmap_lock held and the gate closed.           *)
(***************************************************************************)

\* mmap_fastpath_note_materialized_locked.
NoteMat(c, p) ==
    LET S == {s \in V : c[s].en /\ c[s].base <= p /\ p < c[s].lim}
    IN IF S = {} THEN c
       ELSE LET s == CHOOSE o \in S : TRUE
                lo == IF c[s].mgen = c[s].gen THEN Min({c[s].mlo, p}) ELSE p
                hi == IF c[s].mgen = c[s].gen
                      THEN IF c[s].mhi > p + 1 THEN c[s].mhi ELSE p + 1
                      ELSE p + 1
            IN [c EXCEPT ![s].mgen = c[s].gen, ![s].mlo = lo, ![s].mhi = hi]

Fault(t) ==
    LET p == arg[t] IN
    IF p \notin regions
    THEN /\ IF p \in live THEN Fail("false SIGSEGV on a live page") ELSE UNCHANGED err
         /\ Goto(t, "h_rel")
         /\ UNCHANGED <<lock, ctl, pte, claim>>
    ELSE IF p \in claim
    THEN Goto(t, "h_cw") /\ UNCHANGED <<lock, ctl, pte, claim, err>>
    ELSE IF p \in pte
    THEN /\ ctl' = NoteMat(ctl, p)
         /\ Goto(t, "h_rel")
         /\ UNCHANGED <<lock, pte, claim, err>>
    ELSE \/ /\ pte' = pte \cup {p}
            /\ ctl' = NoteMat(ctl, p)
            /\ Goto(t, "h_rel")
            /\ UNCHANGED <<lock, claim, err>>
         \* Dirty block: claim it, drop mmap_lock keeping the gate, zero it.
         \/ /\ claim' = claim \cup {p}
            /\ lock' = NoOne
            /\ Goto(t, "h_reacq")
            /\ UNCHANGED <<ctl, pte, err>>

\* mmap_lock_reacquire_with_gate.
HReacq(t) ==
    /\ pc[t] = "h_reacq"
    /\ lock = NoOne
    /\ lock' = t
    /\ Goto(t, "h_redrain")
    /\ UNCHANGED <<op, arg, gate, gref, active, ctl, pub, ret,
                   regions, pte, live, claim, dead, err>>

HRedrain(t) ==
    /\ pc[t] = "h_redrain"
    /\ IF ~AllRetEmpty
       THEN Fail("retirement published while a gate reference was retained")
       ELSE IF DrainErr # "none" THEN Fail(DrainErr) ELSE UNCHANGED err
    /\ regions' = DrainedRegions
    /\ pub' = [s \in V |-> <<>>]
    /\ ret' = [s \in V |-> <<>>]
    /\ ctl' = EnvelopeReset(Rewound(t, DrainedRegions, ctl))
    /\ Goto(t, "h_install")
    /\ UNCHANGED <<op, arg, lock, gate, gref, active, pte, live, claim, dead>>

HInstall(t) ==
    /\ pc[t] = "h_install"
    /\ pte' = pte \cup {arg[t]}
    /\ ctl' = NoteMat(ctl, arg[t])
    /\ claim' = claim \ {arg[t]}
    /\ Goto(t, "h_rel")
    /\ UNCHANGED <<op, arg, lock, gate, gref, active, pub, ret,
                   regions, live, dead, err>>

Disabled(cs) == [cs EXCEPT !.gen = @ + 1, !.en = FALSE, !.base = 0, !.lim = 0,
                            !.cur = 0, !.mgen = 0, !.mlo = 0, !.mhi = 0]

DisableAll(c) == [s \in V |-> Disabled(c[s])]

DisableCovering(c, p) ==
    [s \in V |-> IF c[s].en /\ c[s].base <= p /\ p < c[s].lim
                 THEN Disabled(c[s]) ELSE c[s]]

Reserved(c, q, self) ==
    \E s \in V \ {self} : c[s].en /\ c[s].base <= q /\ q < c[s].lim

\* mmap_fastpath_refill_thread_locked then mmap_fastpath_allocate_current_locked,
\* falling back to a generic lazy mapping outside every enabled arena.
HostMmap(t) ==
    LET c == ctl[t]
        keep == c.en /\ c.cur < c.lim
                /\ (c.cur # c.base \/ c.lim - c.base >= ArenaPages)
        gaps == {b \in 1..(NPages - ArenaPages + 1) :
                    /\ Range(b, ArenaPages) \cap regions = {}
                    /\ \A q \in Range(b, ArenaPages) : ~Reserved(ctl, q, t)}
        b == Min(gaps)
        ng == c.gen + 1
        c1 == IF keep THEN ctl
              ELSE IF gaps = {}
              THEN [ctl EXCEPT ![t] = [NoCtl EXCEPT !.gen = ng, !.cgen = c.cgen]]
              ELSE [ctl EXCEPT ![t] = [gen |-> ng, cgen |-> ng, en |-> TRUE,
                                       base |-> b, lim |-> b + ArenaPages,
                                       cur |-> b, mgen |-> 0, mlo |-> 0, mhi |-> 0]]
        pte1 == IF keep \/ gaps = {} THEN pte ELSE pte \ Range(b, ArenaPages)
        a == c1[t]
        generic == {q \in P : q \notin regions /\ ~Reserved(c1, q, NoOne)}
    IN IF a.en /\ a.cur < a.lim
       THEN /\ ctl' = [c1 EXCEPT ![t].cur = a.cur + 1]
            /\ regions' = regions \cup {a.cur}
            /\ live' = live \cup {a.cur}
            /\ pte' = pte1
            /\ IF a.cur \in live \/ a.cur \in regions
               THEN Fail("arena allocation returned a mapped page")
               ELSE UNCHANGED err
       ELSE IF generic = {}
       THEN ctl' = c1 /\ pte' = pte1 /\ UNCHANGED <<regions, live, err>>
       ELSE LET q == Min(generic) IN
            /\ ctl' = c1
            /\ pte' = pte1
            /\ regions' = regions \cup {q}
            /\ live' = live \cup {q}
            /\ IF q \in live THEN Fail("generic mmap returned a live page")
               ELSE UNCHANGED err

HostMunmap(t) ==
    LET p == arg[t] IN
    IF p \in claim
    THEN Goto(t, "h_cw") /\ UNCHANGED <<ctl, regions, pte, live, err>>
    ELSE /\ regions' = regions \ {p}
         /\ pte' = pte \ {p}
         /\ live' = live \ {p}
         /\ ctl' = Rewound(t, regions \ {p}, ctl)
         /\ Goto(t, "h_rel")
         /\ UNCHANGED err

\* Fork snapshot: every live page must be in the region table it sends.
ForkSnapshot(t) ==
    IF claim # {}
    THEN Goto(t, "h_cw") /\ UNCHANGED err
    ELSE /\ IF ~(live \subseteq regions) \/ ~AllRetEmpty \/ PubPages # {}
            THEN Fail("fork snapshot misses a live mapping")
            ELSE UNCHANGED err
         /\ Goto(t, "h_rel")

HOp(t) ==
    /\ pc[t] = "h_op"
    /\ CASE op[t] = "fault" ->
              Fault(t) /\ UNCHANGED <<op, arg, gate, gref, active, pub, ret,
                                      regions, live, dead>>
         [] op[t] = "mmap" ->
              HostMmap(t) /\ Goto(t, "h_rel")
              /\ UNCHANGED <<op, arg, lock, gate, gref, active, pub, ret, claim, dead>>
         [] op[t] = "munmap" ->
              HostMunmap(t)
              /\ UNCHANGED <<op, arg, lock, gate, gref, active, pub, ret, claim, dead>>
         [] op[t] = "revoke" ->
              /\ ctl' = DisableCovering(ctl, arg[t])
              /\ Goto(t, "h_rel")
              /\ UNCHANGED <<op, arg, lock, gate, gref, active, pub, ret,
                             regions, pte, live, claim, dead, err>>
         [] op[t] = "fork" ->
              /\ ctl' = DisableAll(ctl)
              /\ ForkSnapshot(t)
              /\ UNCHANGED <<op, arg, lock, gate, gref, active, pub, ret,
                             regions, pte, live, claim, dead>>
         \* sys_execve waits out materialization claims, because guest_reset
         \* zeroes shim data and the gate count with it.
         [] op[t] = "exec" /\ claim # {} ->
              /\ Goto(t, "h_cw")
              /\ UNCHANGED <<op, arg, lock, gate, gref, active, ctl, pub, ret,
                             regions, pte, live, claim, dead, err>>
         [] op[t] = "exec" /\ claim = {} ->
              /\ gate' = 0
              /\ ctl' = [s \in V |-> NoCtl]
              /\ pub' = [s \in V |-> <<>>]
              /\ ret' = [s \in V |-> <<>>]
              /\ active' = [s \in V |-> FALSE]
              /\ regions' = {}
              /\ pte' = {}
              /\ live' = {}
              /\ Goto(t, "h_rel")
              /\ UNCHANGED <<op, arg, lock, gref, claim, dead, err>>

\* mmap_fastpath_allocate_current_publication_only: raw lock, gate open.
PubOnly(t) ==
    /\ pc[t] = "p_body"
    /\ LET c == ctl[t] IN
       IF gate # 0 \/ ~AllRetEmpty
          \/ ~(c.en /\ c.cgen = c.gen /\ c.cur < c.lim)
          \/ (c.cur = c.base /\ c.lim - c.base < ArenaPages)
       THEN /\ lock' = NoOne
            /\ Goto(t, "h_acq")
            /\ op' = [op EXCEPT ![t] = "mmap"]
            /\ UNCHANGED <<arg, gate, gref, active, ctl, pub, ret,
                           regions, pte, live, claim, dead, err>>
       ELSE /\ regions' = (regions \cup PubPages) \cup {c.cur}
            /\ pub' = [s \in V |-> <<>>]
            /\ ctl' = [ctl EXCEPT ![t].cur = c.cur + 1]
            /\ live' = live \cup {c.cur}
            /\ IF BadPub THEN Fail("publication outside its arena")
               ELSE IF c.cur \in live \/ c.cur \in regions \cup PubPages
               THEN Fail("publication-only path returned a mapped page")
               ELSE UNCHANGED err
            /\ lock' = NoOne
            /\ Goto(t, "h_ret")
            /\ op' = [op EXCEPT ![t] = "none"]
            /\ UNCHANGED <<arg, gate, gref, active, ret, pte, claim, dead>>

CoreNext ==
    \/ \E v \in V :
          \/ GuestMmap(v) \/ GuestFork(v) \/ GuestExec(v)
          \/ \E p \in P : GuestMunmap(v, p) \/ GuestTouch(v, p) \/ GuestRevoke(v, p)
          \/ MPre(v) \/ MAnnc(v) \/ MChk(v) \/ MBody(v)
          \/ UPre(v) \/ UAnnc(v) \/ UChk(v) \/ UBody(v)
          \/ PubOnly(v)
    \/ \E h \in Helpers, p \in P : HelperTouch(h, p)
    \/ \E t \in T :
          \/ HAcq(t) \/ HClose(t) \/ HWait(t) \/ HDrain(t) \/ HOp(t)
          \/ HRel(t) \/ HRet(t) \/ HCondWait(t) \/ HSleep(t)
          \/ HReacq(t) \/ HRedrain(t) \/ HInstall(t)

(***************************************************************************)
(* The TLB. Entries are filled by guest accesses through a valid           *)
(* descriptor. el1_munmap invalidates synchronously (TLBI then DSB before  *)
(* the retire tail). A host writer only records the request; the shim runs *)
(* it when that thread returns to EL0, after mmap_lock is released. An     *)
(* entry for a page the guest unmapped is stale: reaching the page through *)
(* it after the page is mapped again skips the fault that zeroes it.       *)
(***************************************************************************)
HasActor == \E t \in T : pc'[t] # pc[t]
Actor == CHOOSE t \in T : pc'[t] # pc[t]
El1States == {"m_pre", "m_annc", "m_chk", "m_body",
              "u_pre", "u_annc", "u_chk", "u_body"}

TLBStep ==
    IF ~ModelTLB \/ ~HasActor THEN UNCHANGED tl
    ELSE
    LET a == Actor
        left == live \ live'
        cleared == pte \ pte'
        sync == pc[a] = "u_body"
        restart == a \in V /\ ctl'[a].en
                   /\ (ctl'[a].gen # ctl[a].gen \/ ctl'[a].cur < ctl[a].cur)
        reuse == IF FlushArenaOnReuse /\ restart
                 THEN Range(ctl'[a].base, ctl'[a].lim - ctl'[a].base) ELSE {}
        pend1 == [tl.pend EXCEPT ![a] =
                     @ \cup (IF sync THEN {} ELSE cleared) \cup reuse]
        returning == pc[a] = "h_ret"
        flush == (IF sync THEN cleared ELSE {})
                 \cup (IF returning THEN pend1[a] ELSE {})
    IN IF pc[a] = "h_op" /\ op[a] = "exec" /\ pc'[a] = "h_rel"
       THEN tl' = [valid |-> [v \in V |-> {}], stale |-> [v \in V |-> {}],
                   pend |-> [t \in T |-> {}]]
       ELSE tl' = [valid |-> [v \in V |-> (tl.valid[v] \ left) \ flush],
                   stale |-> [v \in V |->
                                 (tl.stale[v] \cup (tl.valid[v] \cap left))
                                 \ flush],
                   pend |-> IF returning THEN [pend1 EXCEPT ![a] = {}]
                            ELSE pend1]

\* A load or store through a valid descriptor caches it.
GuestHit(v, p) ==
    /\ ModelTLB
    /\ Runnable(v)
    /\ p \in pte
    /\ p \notin tl.valid[v]
    /\ tl' = [tl EXCEPT !.valid[v] = @ \cup {p}, !.stale[v] = @ \ {p}]
    /\ UNCHANGED vars

\* A stale entry serves an access the missing descriptor should have faulted.
StaleHit(v, p) ==
    /\ Runnable(v)
    /\ p \notin pte
    /\ p \in tl.stale[v]
    /\ p \in live
    /\ err' = "stale TLB entry reaches a remapped page"
    /\ UNCHANGED <<pc, op, arg, lock, gate, gref, active, ctl, pub, ret,
                   regions, pte, live, claim, dead, tl>>

Next ==
    \/ CoreNext /\ TLBStep
    \/ \E v \in V, p \in P : GuestHit(v, p) \/ StaleHit(v, p)

Spec == Init /\ [][Next]_<<vars, tl>>

(***************************************************************************)
(* Properties.                                                             *)
(***************************************************************************)
NoFailClosed == err = "none"

\* A valid descriptor only ever maps a page the guest holds.
NoStalePte == pte \subseteq live

\* No EL1 producer is past the gate while a host thread that holds the gate
\* rewrites descriptors or reads the drained state.
HostCritical == {"h_drain", "h_op", "h_reacq", "h_redrain", "h_install"}
GateExclusion ==
    \A v \in V : pc[v] \in {"m_body", "u_body"} =>
        \A t \in T : pc[t] \notin HostCritical

\* Every gate reference is held by someone who closed it.
GateAccounting == gate <= Cardinality({t \in T : gref[t]})

GenBound == \A s \in V : ctl[s].gen <= MaxGen

=============================================================================
