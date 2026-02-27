Name:           proxydhcpd
Version:        0.2.0
Release:        1%{?dist}
Summary:        A proxy DHCP server in pure Python 3

License:        GPL-2.0-only
URL:            https://github.com/
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-pip
BuildRequires:  python3-wheel
BuildRequires:  systemd-rpm-macros

Requires:       python3

%description
A full proxy DHCP server compatible with PXE, ported to pure Python 3.
It binds to port 4011 and provides TFTP bootfile location information 
for clients booting via network in parallel with a standard DHCP server.

%prep
%autosetup -n %{name}-%{version}

%build
%pyproject_wheel

%install
%pyproject_install
install -D -p -m 644 %{name}.service %{buildroot}%{_unitdir}/%{name}.service
install -D -p -m 644 proxy.ini %{buildroot}%{_sysconfdir}/proxyDHCPd/proxy.ini

%files
%{_bindir}/proxydhcpd
%{python3_sitelib}/proxydhcpd/
%{python3_sitelib}/proxydhcpd-*.dist-info/
%{_unitdir}/%{name}.service
%dir %{_sysconfdir}/proxyDHCPd
%config(noreplace) %{_sysconfdir}/proxyDHCPd/proxy.ini

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%changelog
* Thu Feb 26 2026 Guilherme Moro <guilherme.moro@gmail.com> - 0.2.0-1
- Modernized proxyDHCPd port to Python 3
- Added robust pyproject.toml and systemd configurations
