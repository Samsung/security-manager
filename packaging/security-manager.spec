Name:       security-manager
Summary:    Security manager and utilities
Version:    1.2.17
Release:    0
Group:      Security/Service
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    security-manager.manifest
Source3:    libsecurity-manager-client.manifest
Source4:    libnss-security-manager.manifest
Source5:    security-manager-tests.manifest
Requires: security-manager-policy
Requires: nether
%if "%{build_type}" == "VALGRIND"
Requires: valgrind
%endif
Requires(post): sqlite3
Requires(post): smack
BuildRequires: cmake
BuildRequires: zip
# BuildRequires: pkgconfig(dlog)
BuildRequires: libattr-devel
BuildRequires: pkgconfig(libprocps)
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(libcap)
BuildRequires: pkgconfig(libsystemd-daemon)
BuildRequires: pkgconfig(libsystemd-journal)
BuildRequires: pkgconfig(libtzplatform-config)
BuildRequires: tizen-platform-config-tools
BuildRequires: pkgconfig(sqlite3)
BuildRequires: pkgconfig(db-util)
BuildRequires: pkgconfig(cynara-admin)
BuildRequires: pkgconfig(cynara-client-async)
BuildRequires: pkgconfig(security-privilege-manager)
BuildRequires: boost-devel
%{?systemd_requires}

%global db_test_dir %{?TZ_SYS_RO_SHARE:%TZ_SYS_RO_SHARE/sm-db-test}%{!?TZ_SYS_RO_SHARE:%_datadir/sm-db-test}

%description
Tizen security manager and utilities

%package -n libsecurity-manager-client
Summary:    Security manager (client)
Group:      Security/Libraries
Requires:   security-manager = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libsecurity-manager-client
Tizen Security manager client library

%package -n libsecurity-manager-client-devel
Summary:    Security manager (client-devel)
Group:      Security/Development
Requires:   libsecurity-manager-client = %{version}-%{release}

%description -n libsecurity-manager-client-devel
Development files needed for using the security manager client

%package -n libnss-security-manager
Summary:    Security Manager NSS library
Group:      Security/Libraries
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libnss-security-manager
Tizen Security Manager NSS library

%package policy
Summary:    Security manager policy
Group:      Security/Access Control
Requires:   sed
Requires(post): security-manager = %{version}-%{release}
Requires(post): cyad
Requires(post): sqlite
Requires(post): tizen-platform-config-tools

%description policy
Set of security rules that constitute security policy in the system

%package -n security-manager-tests
Summary:    Security manager unit test binaries
Group:      Security/Development
Requires:   boost-test

%description -n security-manager-tests
Internal test for security manager implementation.

%package -n license-manager
Summary:    Plugins for cynara service and client
Group:      Security/Development
Requires:   cynara

%description -n license-manager
Package with plugins for cynara.

%prep
%setup -q
cp %{SOURCE1} .
cp %{SOURCE3} .
cp %{SOURCE4} .
cp %{SOURCE5} .

export LDFLAGS+="-Wl,--rpath=%{_libdir}"

%cmake . -DVERSION=%{version} \
        -DBIN_INSTALL_DIR=%{_bindir} \
        -DDB_INSTALL_DIR=%{TZ_SYS_DB} \
        -DLOCAL_STATE_DIR=%{TZ_SYS_VAR} \
        -DSYSTEMD_INSTALL_DIR=%{_unitdir} \
        -DDATA_ROOT_DIR=%{_datadir} \
        -DDB_LOGS=OFF \
        -DDB_TEST_DIR=%{db_test_dir} \
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
        -DCMAKE_VERBOSE_MAKEFILE=ON
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/%{_unitdir}/sockets.target.wants
mkdir -p %{buildroot}/%{_unitdir}/sysinit.target.wants
mkdir -p %{buildroot}/%{_unitdir}/basic.target.wants
mkdir -p %{buildroot}/%{_unitdir}/dbus.service.wants
mkdir -p %{buildroot}/%{_unitdir}/cynara.service.wants
ln -s ../security-manager.socket %{buildroot}/%{_unitdir}/sockets.target.wants/security-manager.socket
ln -s ../security-manager-cleanup.service %{buildroot}/%{_unitdir}/sysinit.target.wants/security-manager-cleanup.service
ln -s ../security-manager-rules-loader.service %{buildroot}/%{_unitdir}/basic.target.wants/security-manager-rules-loader.service
ln -s ../security-manager.service %{buildroot}/%{_unitdir}/dbus.service.wants/security-manager.service
ln -s ../license-manager-agent.service %{buildroot}/%{_unitdir}/cynara.service.wants/license-manager-agent.service

mkdir -p %{buildroot}/%{TZ_SYS_DB}
touch %{buildroot}/%{TZ_SYS_DB}/.security-manager.db
touch %{buildroot}/%{TZ_SYS_DB}/.security-manager.db-journal

install -m 0755 -d %{buildroot}%{TZ_SYS_VAR}/security-manager
install -m 0444 /dev/null %{buildroot}%{TZ_SYS_VAR}/security-manager/apps-labels
install -m 0444 /dev/null %{buildroot}%{TZ_SYS_VAR}/security-manager/policy-version

mkdir -p %{buildroot}/%{db_test_dir}
sqlite3 %{buildroot}/%{db_test_dir}/.security-manager-test.db  <  db/db.sql

%clean
rm -rf %{buildroot}

%post
/sbin/ldconfig
systemctl daemon-reload
if [ $1 = 1 ]; then
    # installation
    systemctl start security-manager.service
    %{_datadir}/security-manager/db/update.sh
fi

if [ $1 = 2 ]; then
    # update
    %{_bindir}/security-manager-migration
    systemctl restart security-manager.service
    %{_datadir}/security-manager/db/update.sh
fi

chsmack -a System %{TZ_SYS_DB}/.security-manager.db
chsmack -a System %{TZ_SYS_DB}/.security-manager.db-journal

chsmack -r -a _ %{TZ_SYS_VAR}/security-manager/

%preun
if [ $1 = 0 ]; then
    # unistall
    systemctl stop security-manager.service
fi

%postun
/sbin/ldconfig
if [ $1 = 0 ]; then
    # unistall
    systemctl daemon-reload
fi

%post -n libsecurity-manager-client -p /sbin/ldconfig

%postun -n libsecurity-manager-client -p /sbin/ldconfig

%post -n libnss-security-manager -p /sbin/ldconfig

%postun -n libnss-security-manager -p /sbin/ldconfig

%post -n license-manager -p /sbin/ldconfig

%postun -n license-manager -p /sbin/ldconfig

%pre
### Workaround for invalid policy versioning mechanism
if [ -e %{TZ_SYS_VAR}/security-manager/policy-version ] && [ x`cat %{TZ_SYS_VAR}/security-manager/policy-version` = x"1" ]
then
    ### Restart versioning, let the update scripts do their work
    echo 0 >%{TZ_SYS_VAR}/security-manager/policy-version
fi

%post policy
%{_datadir}/security-manager/policy/update.sh
%{_bindir}/security-manager-policy-reload

%post -n security-manager-tests
chsmack -a System %{db_test_dir}/.security-manager-test.db
chsmack -a System %{db_test_dir}/.security-manager-test.db-journal

%files -n security-manager
%manifest security-manager.manifest
%license LICENSE
%defattr(-,root,root,-)
%attr(755,root,root) %{_bindir}/security-manager-migration
%attr(755,root,root) %{_bindir}/security-manager
%attr(755,root,root) %{_bindir}/security-manager-cmd
%attr(755,root,root) %{_bindir}/security-manager-cleanup
%attr(755,root,root) %{_sysconfdir}/gumd/useradd.d/50_security-manager-add.post
%attr(755,root,root) %{_sysconfdir}/gumd/userdel.d/50_security-manager-remove.pre
%config(noreplace) %attr(444,root,root) %{TZ_SYS_VAR}/security-manager/apps-labels
%dir %attr(711,root,root) %{TZ_SYS_VAR}/security-manager/
%dir %attr(700,root,root) %{TZ_SYS_VAR}/security-manager/rules
%dir %attr(700,root,root) %{TZ_SYS_VAR}/security-manager/rules-merged

%{_libdir}/libsecurity-manager-commons.so.*
%attr(-,root,root) %{_unitdir}/security-manager.*
%attr(-,root,root) %{_unitdir}/security-manager-cleanup.*
%attr(-,root,root) %{_unitdir}/security-manager-rules-loader.service
%attr(-,root,root) %{_unitdir}/basic.target.wants/security-manager-rules-loader.service
%attr(-,root,root) %{_unitdir}/sockets.target.wants/security-manager.*
%attr(-,root,root) %{_unitdir}/sysinit.target.wants/security-manager-cleanup.*
%config(noreplace) %attr(0600,root,root) %{TZ_SYS_DB}/.security-manager.db
%config(noreplace) %attr(0600,root,root) %{TZ_SYS_DB}/.security-manager.db-journal

%{_datadir}/security-manager/db
%attr(755,root,root) %{_datadir}/%{name}/db/update.sh
%attr(755,root,root) %{_sysconfdir}/opt/upgrade/240.security-manager.db-update.sh

%files -n libsecurity-manager-client
%manifest libsecurity-manager-client.manifest
%license LICENSE
%defattr(-,root,root,-)
%{_libdir}/libsecurity-manager-client.so.*

%files -n libsecurity-manager-client-devel
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/libsecurity-manager-client.so
%{_libdir}/libsecurity-manager-commons.so
%{_includedir}/security-manager/*.h
%{_libdir}/pkgconfig/security-manager.pc

%files -n libnss-security-manager
%manifest libnss-security-manager.manifest
%license LICENSE
%defattr(-,root,root,-)
%%attr(-,root,root) %{_unitdir}/dbus.service.wants/security-manager.service
%{_libdir}/libnss_securitymanager.so.*

%files -n security-manager-policy
%manifest %{name}.manifest
%license LICENSE
%config(noreplace) %{TZ_SYS_VAR}/security-manager/policy-version
%{_datadir}/security-manager/policy
%attr(755,root,root) %{_bindir}/security-manager-policy-reload
%attr(755,root,root) %{_sysconfdir}/opt/upgrade/241.security-manager.policy-update.sh

%files -n security-manager-tests
%manifest %{name}.manifest
%attr(755,root,root) %{_bindir}/security-manager-unit-tests
%attr(0600,root,root) %{db_test_dir}/.security-manager-test.db
%attr(0600,root,root) %{db_test_dir}/.security-manager-test.db-journal

%files -n license-manager
%{_libdir}/cynara/plugin/client/liblicense-manager-plugin-client.so
%{_libdir}/cynara/plugin/service/liblicense-manager-plugin-service.so
%{_bindir}/license-manager-agent
%attr(-,root,root) %{_unitdir}/cynara.service.wants/license-manager-agent.service
%attr(-,root,root) %{_unitdir}/license-manager-agent.service

