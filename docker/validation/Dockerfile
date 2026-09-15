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
FROM almalinux:8

RUN dnf -y install --setopt=install_weak_deps=False \
        python3.11 python3.11-pip \
        openscap-scanner scap-security-guide \
        procps-ng findutils grep sed gawk which \
    && dnf clean all

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
# file, and task naming is the operator's convention rather than ansible-lint's business.
RUN printf '%s\n' \
    'skip_list:' \
    '  - meta-no-info' \
    '  - name[template]' \
    '  - name[casing]' \
    'offline: true' \
    > /etc/ansible-lint.yml

ENV ANSIBLE_LINT_CONFIG=/etc/ansible-lint.yml
ENV ANSIBLE_LOCALHOST_WARNING=False
ENV ANSIBLE_DEPRECATION_WARNINGS=False

WORKDIR /tmp/stigsmith
CMD ["sleep", "infinity"]
