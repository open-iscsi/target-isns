Name:       target-isns
Summary:    iSNS support for Linux kernel target
Version:    0.3
Release:    1
Source:     %{name}-%{version}.tar.gz
License:    GPLv2+
ExclusiveOS: linux
Group:      System Environment/Kernel
URL:        https://github.com/cvubrugier/target-isns
BuildRoot:  %{_tmppath}/%{name}-%{version}-build
BuildRequires: gcc flex glibc-devel make
BuildRequires: cmake

%description
Target-isns is an Internet Storage Name Service (iSNS) client for the
Linux LIO iSCSI target. It allows to register LIO iSCSI targets to an
iSNS server.

The iSNS protocol is specified in
[RFC 4171](http://tools.ietf.org/html/rfc4171) and its purpose is to
make easier to discover, manage, and configure iSCSI devices. With
iSNS, iSCSI targets can be registered to a central iSNS server and
initiators can be configured to discover the targets by asking the
iSNS server.

%prep
%setup -n %{name}-%{version}

%build
mkdir build
cd build
cmake -D CMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_C_FLAGS="${RPM_OPT_FLAGS}" ..
%{__make}

%install
cd build
%{__make} DESTDIR=${RPM_BUILD_ROOT} install

%clean
[ "${RPM_BUILD_ROOT}" != "/" -a -d ${RPM_BUILD_ROOT} ] && \
  rm -rf ${RPM_BUILD_ROOT}

%post
# nothing to do?

%postun
# nothing to do?

%pre
# nothing to do?

%preun
# nothing to do?

%files
%defattr(-,root,root)
%dir /etc
%attr(0600,root,root) %config(noreplace) /etc/target-isns.conf
%dir /usr/bin
/usr/bin/target-isns
%doc %{_mandir}/man8/target-isns.8.gz

%changelog
