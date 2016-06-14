%define sd_python_req systemd-python
%{?fedora: %define sd_python_req python2-systemd}
%if 0%{?rhel} >= 8
	%define sd_python_req python2-systemd
%endif

%define daemonuser pwadmin
%define daemongroup pwadmin
%define pwresetd_service qbic-pwresetd.service
%define pwresetd_socket qbic-pwresetd.socket

Name:		qbic-pwresetd
Version:	1.0.2
Release:	1%{?dist}
Summary:	Password reset daemon for QBiC LDAP

Group:		System Environment/Daemons
License:	GPLv3
URL:		http://portal.qbic.uni-tuebingen.de/
Source0:	qbic_pwresetd-%{version}.tar.gz

BuildArch:	noarch
BuildRequires:	python2-devel, python-setuptools, systemd

Requires(pre):	shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

Requires:	%{sd_python_req}
Requires:	python-ldap, python-pwquality, pytz, MySQL-python
# rpmlint complains about the following:says it should be autodiscovered, but it is not
Requires:	python-passlib
Provides:	%{name} = %{version}-%{release}
# Provides:	%%python_provide %%{name}

%description
Implements a password reset centralized service for the QBiC LDAP users

%prep
%setup -q -n qbic_pwresetd-%{version}


%build
CFLAGS="$RPM_OPT_FLAGS" %{__python} setup.py build


%install
%{__python} setup.py install --skip-build --root $RPM_BUILD_ROOT
install -d -m 0755 ${RPM_BUILD_ROOT}%{_sbindir}
install -d -m 0755 ${RPM_BUILD_ROOT}%{_unitdir}
install -d -m 0750 ${RPM_BUILD_ROOT}%{_sysconfdir}/pwreset
install -m 0644 qbic-pwresetd.socket ${RPM_BUILD_ROOT}%{_unitdir}
install -m 0644 qbic-pwresetd.service ${RPM_BUILD_ROOT}%{_unitdir}
mv $RPM_BUILD_ROOT/usr/bin/%{name} ${RPM_BUILD_ROOT}%{_sbindir}/%{name}


%pre
getent group %{daemongroup} >/dev/null || groupadd -r %{daemongroup} || exit 1
getent passwd %{daemonuser} >/dev/null || \
	useradd -r -g %{daemongroup} -d / -s /sbin/nologin \
		-c "LDAP password reset" %{daemonuser} || exit 1
exit 0


%post
%systemd_post %{pwresetd_service} %{pwresetd_socket}

%preun
%systemd_preun %{pwresetd_service} %{pwresetd_socket}

%postun
%systemd_postun_with_restart %{pwresetd_service} %{pwresetd_socket}


%files
%doc
%attr(750, root, pwadmin) %{_sysconfdir}/pwreset
%{_sbindir}/%{name}
%{_bindir}/pwreset
%{python_sitelib}/*
%{_unitdir}/*


%changelog
* Wed Feb 24 2016 Enrico Tagliavini <enrico.tagliavini@uni-tuebingen.de>  - 0.9_beta-2
- Create the pwadmin user and group
- Include %{_sysconfdir}/pwreset

* Tue Feb 23 2016 Enrico Tagliavini <enrico.tagliavini@uni-tuebingen.de>  - 0.9_beta-1
- first release
