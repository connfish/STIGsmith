# The image the validation loop applies generated remediation in.
#
# Build it once, before validation will do anything useful:
#   docker build -t stigsmith/validation:el8 docker/validation
#
# Everything is installed at build time on purpose. Target environments are frequently air-gapped, so a loop that
# fetched ansible-lint at run time would hang rather than fail fast. Build this where you have a mirror, then move
# the image.
#
# AlmaLinux 8 rather than a UBI: the RHEL 8 STIG's fixes assume el8 paths and package names, and Alma carries the
# SCAP Security Guide content in its repositories where UBI does not.
#
# The second group is the packages whose configuration files the RHEL 8 STIG edits. None of their services can run
# in a container, and the loop does not pretend otherwise, but a rule that sets a line in sshd_config, audit.rules,
# rsyslog.conf, firewalld.conf, chrony.conf, sudoers or pwquality.conf can only apply and be re-checked if the file
# exists. Measured on a real model: without openssh-server every SSH rule failed with "Destination
# /etc/ssh/sshd_config does not exist" before its YAML was ever judged.
FROM almalinux:8

RUN dnf -y install --setopt=install_weak_deps=False \
        python3.11 python3.11-pip \
        openscap-scanner scap-security-guide \
        procps-ng findutils grep sed gawk which \
        openssh-server audit audispd-plugins rsyslog firewalld chrony sudo libpwquality libuser aide policycoreutils \
        selinux-policy-targeted authselect dconf tmux \
    && dnf clean all \
    # Host keys, so `sshd -t` (the validate step every sshd_config edit should carry) can run at all.
    && ssh-keygen -A

# ansible-core from pip rather than the distro package: the loop's lint and syntax-check behaviour should not drift
# with whatever ansible version a base image happens to ship.
RUN python3.11 -m pip install --no-cache-dir \
        'ansible-core==2.16.*' \
        'ansible-lint==24.*' \
    && ln -sf /usr/local/bin/ansible-playbook /usr/bin/ansible-playbook \
    && ln -sf /usr/local/bin/ansible-lint /usr/bin/ansible-lint

# The collections generated remediation is most likely to reference.
RUN ansible-galaxy collection install ansible.posix community.general

# Quieten the checks that are meaningless for a single generated task list: there is no role here to have a meta
# file, and task naming and line length are the operator's conventions rather than ansible-lint's business. Measured
# on a real model: a 164-character task name (the rule's full DISA title) was the only thing wrong with an otherwise
# correct remediation, and line length is not what this loop exists to prove.
RUN printf '%s\n' \
    'skip_list:' \
    '  - meta-no-info' \
    '  - name[template]' \
    '  - name[casing]' \
    '  - yaml[line-length]' \
    'offline: true' \
    > /etc/ansible-lint.yml
# ansible-lint has no environment variable for its config; the loop passes this path with -c (ValidationOptions).

ENV ANSIBLE_LOCALHOST_WARNING=False
ENV ANSIBLE_DEPRECATION_WARNINGS=False

WORKDIR /tmp/stigsmith
CMD ["sleep", "infinity"]
