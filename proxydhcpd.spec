%if 0%{?suse_version}
%define pythons python311
%endif

Name:           proxydhcpd
Version:        0.3.3
Release:        1%{?dist}
Summary:        A proxy DHCP server in pure Python 3
License:        GPL-2.0-only
URL:            https://github.com/gmoro/proxyDHCPd
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  systemd-rpm-macros
BuildRequires:  python3-devel

%if 0%{?suse_version}
BuildRequires:  python-rpm-macros
BuildRequires:  fdupes
BuildRequires:  %{python_module pip}
BuildRequires:  %{python_module wheel}
BuildRequires:  %{python_module setuptools}
%else
# --- Fedora static PEP-517 backend requirements ---
BuildRequires:  python3-pip
BuildRequires:  python3-setuptools >= 61.0
BuildRequires:  python3-wheel
%endif

Requires:       python3
%{?systemd_requires}

%description
A full proxy DHCP server compatible with PXE, ported to pure Python 3.
It binds to port 4011 and provides TFTP bootfile location information 
for clients booting via network in parallel with a standard DHCP server.

%prep
%autosetup -n %{name}-%{version}

%if !0%{?suse_version}
%{expand:%%generate_buildrequires}
%pyproject_buildrequires
%endif

%build
%pyproject_wheel

%install
%pyproject_install
install -D -p -m 644 %{name}.service %{buildroot}%{_unitdir}/%{name}.service
install -D -p -m 644 proxy.ini %{buildroot}%{_sysconfdir}/%{name}/proxy.ini

%if 0%{?suse_version}
# Remove python-rpm-macros version suffix from the binary for a standalone app
mv %{buildroot}%{_bindir}/%{name}-* %{buildroot}%{_bindir}/%{name} || :
%fdupes %{buildroot}%{$python_sitelib}
%else
# Generate the dynamic file manifest for Fedora via pyproject-rpm-macros
%pyproject_save_files %{name}
%endif

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%if !0%{?suse_version}
# --- Fedora native files (with pyproject filtering) ---
%files -n %{name} -f %{pyproject_files}
%else
# --- openSUSE native files (with unified python3.x wildcards) ---
%files
%{python_sitelib}/%{name}/
%{python_sitelib}/%{name}-*.dist-info/
%endif
%license LICENSE
%doc README.md CHANGELOG.md
%{_bindir}/%{name}
%{_unitdir}/%{name}.service
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/proxy.ini

%changelog
* Thu Mar 26 2026 Guilherme Moro <guilherme.moro@gmail.com> - 0.3.2-1
- Renamed gpl-2.0.txt to LICENSE for better build system compatibility
- Reverted pyproject.toml license field to legacy file format
- Bumped version to 0.3.2

* Thu Mar 26 2026 Guilherme Moro <guilherme.moro@gmail.com> - 0.3.1-1
- Unified cross-distro spec: robust support for Fedora pyproject-rpm-macros and openSUSE python-rpm-macros
- Implemented Fedora %pyproject_save_files and openSUSE %python_expand %fdupes
- Fixed openSUSE Leap 15.6 build failures and Tumbleweed macro recursion
- Added GitHub Actions workflow for automated PyPI and GitHub releases
- Bounded version bump to 0.3.1

* Thu Mar 05 2026 Guilherme Moro <guilherme.moro@gmail.com> - 0.3.0-1
- Modernised CLI: replaced getopt with argparse (--version, --help, --config, --daemon, --proxy-only)
- Added __version__ and dynamic versioning via pyproject.toml
- Added PyPI classifiers and project URLs
- Cleaned Python 2 compatibility shims
- Added MANIFEST.in, CHANGELOG.md
- Hardened .gitignore for test artifacts
- Unified Fedora/openSUSE Application Spec profile

* Thu Feb 26 2026 Guilherme Moro <guilherme.moro@gmail.com> - 0.2.0-1
- Modernized proxyDHCPd port to Python 3
- Added robust pyproject.toml and systemd configurations
