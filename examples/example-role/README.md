# example-role

A **synthetic** Ansible role, written for Stigsmith's tests. It is not anybody's real role and it is
not a role you should run.

Constraint 5 in the project README: Stigsmith never vendors someone else's Ansible role. The
convention index reads a role from a path supplied at runtime
(`Stigsmith:Generation:ConventionRole:Path`). This directory exists only so the indexer and the
retrieval tests have something to index, and so the house conventions it demonstrates are ones this
repository owns.

The conventions here are deliberately distinctive, so a test can tell whether retrieval actually
transferred them rather than producing generic Ansible:

| Convention | This role's choice |
|---|---|
| Variable prefix | `stigsmith_rhel8_` |
| Per-rule toggle | `stigsmith_rhel8_rule_<vuln number>` |
| Tags | STIG version id, `V-` number, `CAT1`/`CAT2`/`CAT3`, severity, subsystem |
| Handler names | lowercase verb-first: `restart sshd`, `reload sysctl` |
| Module names | fully qualified (`ansible.builtin.lineinfile`) |
| Guard | every task is `when: stigsmith_rhel8_rule_<n>` |
