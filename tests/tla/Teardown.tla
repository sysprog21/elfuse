----------------------------- MODULE Teardown -----------------------------
(***************************************************************************)
(* Thread-group teardown: the fork quiesce window (thread_quiesce_siblings, *)
(* thread_fork_barrier_check, thread_resume_siblings in src/runtime/thread.c) *)
(* against the execve reap (thread_exec_de_thread) and the vCPU run loop in *)
(* src/syscall/proc.c.                                                     *)
(*                                                                         *)
(* Each step that runs under thread_lock is one atomic action. Bounded     *)
(* waits are modelled as a timeout that may fire once the condition it was *)
(* bounding can no longer be met promptly.                                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Leader,       \* the main thread; exec runs here
          Workers,      \* worker threads
          None,
          KickLatched,  \* hv_vcpus_exit on a vCPU outside hv_vcpu_run is kept
          El1Escape,    \* a CANCELED exit at EL1 resumes without the barrier
          SignalEscape, \* a CANCELED exit with a pending signal resumes after delivery
          LoopTopBarrier, \* the loop top parks at the barrier when back at EL0
          ForkAttention   \* the fork raises shim attention before it kicks

Th == {Leader} \cup Workers

VARIABLES st, kick, counted, sig, forkActive, forker, qcount, target, execActive

vars == <<st, kick, counted, sig, forkActive, forker, qcount, target, execActive>>

Init ==
    /\ st = [t \in Th |-> "guest"]
    /\ kick = [t \in Th |-> FALSE]
    /\ counted = [t \in Th |-> FALSE]
    /\ sig = [t \in Th |-> FALSE]
    /\ forkActive = FALSE
    /\ forker = None
    /\ qcount = 0
    /\ target = 0
    /\ execActive = FALSE

Set(t, s) == st' = [st EXCEPT ![t] = s]
InVcpu(t) == st[t] \in {"guest", "el1"}
ExecStop(t) == execActive /\ t # Leader

(***************************************************************************)
(* The run loop.                                                           *)
(***************************************************************************)

\* Guest code enters the EL1 shim, makes a syscall, or gets a signal queued.
GuestEl1(t) == st[t] = "guest" /\ Set(t, "el1")
               /\ UNCHANGED <<kick, counted, sig, forkActive, forker, qcount, target, execActive>>
\* With attention raised the shim leaves through HVC #5 instead of ERET.
El1Return(t) == st[t] = "el1"
               /\ Set(t, IF ForkAttention /\ forkActive THEN "loop" ELSE "guest")
               /\ UNCHANGED <<kick, counted, sig, forkActive, forker, qcount, target, execActive>>
GuestSyscall(t) == st[t] = "guest" /\ Set(t, "sys")
               /\ UNCHANGED <<kick, counted, sig, forkActive, forker, qcount, target, execActive>>
QueueSignal(t) == st[t] # "gone" /\ ~sig[t] /\ sig' = [sig EXCEPT ![t] = TRUE]
               /\ UNCHANGED <<st, kick, counted, forkActive, forker, qcount, target, execActive>>
SyscallReturn(t) == st[t] = "sys" /\ Set(t, "loop")
               /\ UNCHANGED <<kick, counted, sig, forkActive, forker, qcount, target, execActive>>

\* The barrier: count an owed answer and park.
Park(t) ==
    /\ Set(t, "barrier")
    /\ IF counted[t]
       THEN counted' = [counted EXCEPT ![t] = FALSE] /\ qcount' = qcount + 1
       ELSE UNCHANGED <<counted, qcount>>

\* Loop top at EL0: exec stop, then hv_vcpu_run. A pending kick makes
\* hv_vcpu_run return before any guest instruction runs.
LoopTop(t) ==
    /\ st[t] = "loop"
    /\ IF ExecStop(t)
       THEN Set(t, "exiting") /\ UNCHANGED <<kick, counted, qcount>>
       ELSE IF LoopTopBarrier /\ forkActive
       THEN Park(t) /\ UNCHANGED kick
       ELSE IF kick[t]
       THEN Set(t, "cancel") /\ kick' = [kick EXCEPT ![t] = FALSE]
            /\ UNCHANGED <<counted, qcount>>
       ELSE Set(t, "guest") /\ UNCHANGED <<kick, counted, qcount>>
    /\ UNCHANGED <<sig, forkActive, forker, target, execActive>>

\* Loop top with the vCPU stopped inside the EL1 window. It cannot park here:
\* retire.producer_active may be set, and the forker's gate close waits for it.
LoopTopEl1(t) ==
    /\ st[t] = "loop_el1"
    /\ IF ExecStop(t)
       THEN Set(t, "exiting") /\ UNCHANGED kick
       ELSE IF kick[t]
       THEN Set(t, "cancel_el1") /\ kick' = [kick EXCEPT ![t] = FALSE]
       ELSE Set(t, "el1") /\ UNCHANGED kick
    /\ UNCHANGED <<counted, sig, forkActive, forker, qcount, target, execActive>>

\* A kick takes effect inside hv_vcpu_run.
Canceled(t) ==
    /\ InVcpu(t) /\ kick[t]
    /\ kick' = [kick EXCEPT ![t] = FALSE]
    /\ Set(t, IF st[t] = "el1" THEN "cancel_el1" ELSE "cancel")
    /\ UNCHANGED <<counted, sig, forkActive, forker, qcount, target, execActive>>

\* Resuming at EL1 is how the run loop converges; the window ends at EL0.
CancelEl1(t) ==
    /\ st[t] = "cancel_el1"
    /\ IF ExecStop(t) THEN Set(t, "exiting")
       ELSE IF El1Escape THEN Set(t, "loop_el1")
       ELSE Set(t, "cancel")
    /\ UNCHANGED <<kick, counted, sig, forkActive, forker, qcount, target, execActive>>

\* handle_canceled: exec stop, signal delivery, then the fork barrier.
Cancel(t) ==
    /\ st[t] = "cancel"
    /\ IF ExecStop(t)
       THEN Set(t, "exiting") /\ UNCHANGED <<counted, sig, qcount>>
       ELSE IF SignalEscape /\ sig[t]
       THEN Set(t, "loop") /\ sig' = [sig EXCEPT ![t] = FALSE]
            /\ UNCHANGED <<counted, qcount>>
       ELSE IF forkActive
       THEN Park(t) /\ UNCHANGED sig
       ELSE Set(t, "loop") /\ UNCHANGED <<counted, sig, qcount>>
    /\ UNCHANGED <<kick, forkActive, forker, target, execActive>>

\* The barrier holds until the window closes; an exec stop bounds it.
BarrierLeave(t) ==
    /\ st[t] = "barrier"
    /\ ~forkActive \/ ExecStop(t)
    /\ Set(t, "loop")
    /\ UNCHANGED <<kick, counted, sig, forkActive, forker, qcount, target, execActive>>

\* thread_deactivate hands an unanswered count back.
Exit(t) ==
    /\ st[t] = "exiting"
    /\ Set(t, "gone")
    /\ IF forkActive /\ counted[t]
       THEN counted' = [counted EXCEPT ![t] = FALSE] /\ target' = target - 1
       ELSE UNCHANGED <<counted, target>>
    /\ UNCHANGED <<kick, sig, forkActive, forker, qcount, execActive>>

(***************************************************************************)
(* Fork.                                                                   *)
(***************************************************************************)
Others(t) == {u \in Th \ {t} : st[u] # "gone"}

ForkArm(t) ==
    /\ st[t] = "guest" /\ ~forkActive
    /\ IF execActive
       THEN UNCHANGED <<st, kick, counted, forkActive, forker, qcount, target>>
       ELSE /\ Set(t, "f_wait")
            /\ forkActive' = TRUE
            /\ forker' = t
            /\ counted' = [u \in Th |-> u \in Others(t)]
            /\ qcount' = 0
            /\ target' = Cardinality(Others(t))
            /\ kick' = [u \in Th |->
                          IF u \in Others(t) /\ (InVcpu(u) \/ KickLatched)
                          THEN TRUE ELSE kick[u]]
    /\ UNCHANGED <<sig, execActive>>

\* The 100 ms wait: it ends when every counted sibling answered, or times out
\* once no straggler can answer promptly. That is one blocked in host code (a
\* syscall, or the leader inside execve), or one still parked from the
\* previous window: it was counted again when this window armed but answers
\* only on barrier entry, so it never answers this one.
Stragglers(t) == {u \in Others(t) : counted[u]}
BlockedInHost == {"sys", "e_waitfork", "e_reap", "barrier"}
ForkProceed(t) ==
    /\ st[t] = "f_wait"
    /\ \/ qcount >= target
       \/ \A u \in Stragglers(t) : st[u] \in BlockedInHost
    /\ Set(t, "f_snap")
    /\ UNCHANGED <<kick, counted, sig, forkActive, forker, qcount, target, execActive>>

ForkDone(t) ==
    /\ st[t] = "f_snap"
    /\ Set(t, "loop")
    /\ forkActive' = FALSE
    /\ forker' = None
    /\ qcount' = 0
    /\ target' = 0
    /\ counted' = [u \in Th |-> FALSE]
    /\ UNCHANGED <<kick, sig, execActive>>

(***************************************************************************)
(* execve on the leader.                                                   *)
(***************************************************************************)
ExecStart ==
    /\ st[Leader] = "guest"
    /\ Set(Leader, "e_waitfork")
    /\ UNCHANGED <<kick, counted, sig, forkActive, forker, qcount, target, execActive>>

\* Wait for an open fork window to close. The 1 s bound is not modelled: past
\* it the code proceeds into a known overlap, which NoOverlap would report.
ExecPublish ==
    /\ st[Leader] = "e_waitfork"
    /\ ~forkActive
    /\ Set(Leader, "e_reap")
    /\ execActive' = TRUE
    /\ UNCHANGED <<kick, counted, sig, forkActive, forker, qcount, target>>

\* thread_wake_all_blocked re-kicks every running sibling each iteration.
ExecPoke ==
    /\ st[Leader] = "e_reap"
    /\ \E u \in Workers : InVcpu(u) /\ ~kick[u]
    /\ kick' = [u \in Th |-> IF u \in Workers /\ InVcpu(u) THEN TRUE ELSE kick[u]]
    /\ UNCHANGED <<st, counted, sig, forkActive, forker, qcount, target, execActive>>

ExecReset ==
    /\ st[Leader] = "e_reap"
    /\ \A u \in Workers : st[u] = "gone"
    /\ Set(Leader, "loop")
    /\ execActive' = FALSE
    /\ UNCHANGED <<kick, counted, sig, forkActive, forker, qcount, target>>

Next ==
    \/ \E t \in Th :
          \/ GuestEl1(t) \/ El1Return(t) \/ GuestSyscall(t) \/ QueueSignal(t)
          \/ SyscallReturn(t) \/ LoopTop(t) \/ LoopTopEl1(t)
          \/ Canceled(t) \/ CancelEl1(t)
          \/ Cancel(t) \/ BarrierLeave(t) \/ Exit(t)
          \/ ForkArm(t) \/ ForkProceed(t) \/ ForkDone(t)
    \/ ExecStart \/ ExecPublish \/ ExecPoke \/ ExecReset

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Properties.                                                             *)
(***************************************************************************)

\* No sibling runs guest code while the forker copies guest memory.
QuietSnapshot ==
    \A t \in Th : st[t] = "f_snap" => \A u \in Th \ {t} : ~InVcpu(u)

\* The fork window and the exec teardown never overlap.
NoOverlap == ~(forkActive /\ execActive)

CountSane == qcount >= 0 /\ target >= 0

=============================================================================
