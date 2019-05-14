#
# Makefile to manage/test catalogic-dpx containers
#
# useful functions
#
define assert_macro
	@if [ "$($(1))" == "" ] ; then echo "$(1) must be defined" ; exit -1 ; fi
endef

#
# default - short descriptions of the targets in this Makefile
#
help: 
	@echo 'available targets:'
	@echo '	== environment related =='
	@echo '	start - bring up the stack \"dpx\"'
	@echo '	status - show status of the stack \"dpx\"'
	@echo '	stop - bring down the stack \"dpx\"'
	@echo '	clean - clean up the environment'
	@echo '	update - update stack services'
	@echo '	== to login to dpx and save the authentication token in the local file =='
	@echo '	login'
	@echo '	== some tests on the rest svc =='
	@echo '	t.rest.get.policies - list policies'
	@echo '	t.rest.post.node_groups REST_NODEGROUP_NAME=<nodegroup name> - add a node_group'
	@echo '	t.rest.get.node_groups - list node_groups'
	@echo '	t.rest.post.nodes REST_NODEGROUP_NAME=<nodegroup name> REST_NODE_NAME=<node name> - add a node'
	@echo '	t.rest.get.nodes - list nodes'
	@echo '	t.rest.post.vcenters REST_NODEGROUP_NAME=<nodegroup name> REST_VCENTER_ID=<vcenter id> REST_VCENTER_HOST=<vcenter host> REST_VCENTER_USERNAME=<vcenter username> REST_VCENTER_PASSWORD=<vcenter password> - add a vcenter'
	@echo '	t.rest.get.vcenters - list vcenters'
	@echo '	t.rest.get.vmobjects REST_VCENTER_ID=<vcenter name> - list vm objects for the vcenter'
	@echo '	t.rest.patch.vmobjects REST_VCENTER_ID=<vcenter name> REST_POLCICY_ID=<policy name> REST_OBJECT_ID=<vm object id> = update the vm object at vcenter with policy'
	@echo '	== some tests on the vplugin manager svc =='
	@echo '	t.vpmgr.put.config - re-read the config files; re-inits the service'
	@echo '	t.vpmgr.get.config - prints the current config'
	@echo '	t.vpmgr.get.dpx_plugins - lists the available dpx plugins'
	@echo '	t.vpmgr.get.vcenters - lists the available vcenters'
	@echo '	t.vpmgr.get.vcenter.dpx_plugins VPMGR_VCENTER_ID=<vcenter id> - gets the dpx_plugin status at the vcenter'
	@echo '	t.vpmgr.patch.vcenter.dpx_plugins.install VPMGR_VCENTER_ID=<vcenter id> VPLUGIN_VER=<plugin ver to install> - install the specified plugin to the specified vcenter'
	@echo '	t.vpmgr.patch.vcenter.dpx_plugins.uninstall VPMGR_VCENTER_ID=<vcenter id> - unisntall the dpx plugin from the specified vcenter'

# detect OS then detect hostname, save in 'THIS_HOST'
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  DOCKER0_HOST = $(shell ip addr show docker0 | grep 'inet ' | awk '{print $$2}' | cut -f1 -d'/')
  DOCKER_GWBR_HOST = $(shell ip addr show docker_gwbridge | grep 'inet ' | awk '{print $$2}' | cut -f1 -d'/')
  THIS_HOST_LIST = $(filter-out $(DOCKER0_HOST) $(DOCKER_GWBR_HOST),$(shell hostname -I))
  THIS_HOST = $(firstword $(THIS_HOST_LIST))
endif
ifeq ($(UNAME_S),Darwin)
# en1 is the WiFi port on a Macbook (use en0 for the Eth link)
  THIS_HOST = $(shell ipconfig getifaddr en1)
endif

# choose docker execution
DOCKER=docker
#DOCKER=sudo docker

# choose curl execution
CURL=curl -k
#CURL=curl -k -v

# post-curl processing.
# following uses jq to prettify the output and save a copy in a local file: out.json
JQ=| jq . | tee out.json

# 
# bring up the stack
.PHONY: start start-x
start: 
	rm -rf dpx.env
	$(MAKE) start-x

start-x: opt keys stack-logs dpx.env dpx-vplugin-mgr.env dpx-apigateway.env plugins
	. ./dpx-container-tags && $(DOCKER) stack deploy -c dpx.yml dpx --with-registry-auth

# check the status of the stack
status:
	$(DOCKER) stack services dpx

# bring down the stack
stop:
	-$(DOCKER) stack rm dpx

# clean up
clean: stop
	rm -rf auth_token cookies.txt out.json dpx.env dpx-apigateway.env dpx-vplugin-mgr.env

distclean: clean
	rm -rf keys opt-auth opt-apigateway stack-logs dpx-apigateway*.env dpx-vplugin-mgr*.env certs-selfsigned certs-letsencrypt api_key catalogic-dpx-ms.id certbot plugins

# update docker services
update:
	$(DOCKER) stack rm dpx
	./stack-wait.sh
	git pull
	. ./dpx-container-tags && $(DOCKER) stack deploy -c dpx.yml dpx --with-registry-auth

#
# dpx.env contains env vars shared across various containers
#
dpx.env: api_key
	echo "DPX_MASTER_HOST=$(THIS_HOST)" > $@
	echo "DOCKER_HOST_IP=$(THIS_HOST)" >> $@
	echo "DPX_INTERNAL_SECRET_KEY=$(shell cat api_key)" >> $@

# api_key is the shared secret amongst containers
api_key:
	cat /dev/urandom | base64 | head -c 64 > $@

#
# dpx-vplugin-mgr.env contains env vars for container vplugin-mgr
#
ifndef DPX_VPLUGIN_MGR_DEFAULT
DPX_VPLUGIN_MGR_DEFAULT=real
#DPX_VPLUGIN_MGR_DEFAULT=sim
endif
# if not there, default action to create it
dpx-vplugin-mgr.env: 
	$(MAKE) set.vplugin-mgr.$(DPX_VPLUGIN_MGR_DEFAULT)

.PHONY: set.vplugin-mgr.real
set.vplugin-mgr.real: dpx-vplugin-mgr-real.env
	ln -sf $< dpx-vplugin-mgr.env
dpx-vplugin-mgr-real.env: 
	echo "SERVER_SSL_THUMBPRINT=$(shell cat certs-selfsigned/keystore.jks.thumbprint)" > $@
	echo 'AUTH_URL_FORMAT=http://%s/auth' >> $@
	echo 'DPX_MASTER_URL_FORMAT=http://%s/app/api' >> $@

.PHONY: set.vplugin-mgr.sim
set.vplugin-mgr.sim: dpx-vplugin-mgr-sim.env
	ln -sf $< dpx-vplugin-mgr.env
dpx-vplugin-mgr-sim.env: 
	echo "SERVER_SSL_THUMBPRINT=$(shell cat certs-selfsigned/keystore.jks.thumbprint)" > $@
	echo 'AUTH_URL_FORMAT=http://%s/auth' >> $@
	echo 'DPX_MASTER_URL_FORMAT=http://%s/app/api' >> $@
	echo "SPRING_PROFILES_ACTIVE=simulation" >> $@

#
# dpx-apigateway.env contains env vars for container apigateway
#
# if not there, default action to create it
ifndef DPX_CERT_DEFAULT
#DPX_CERT_DEFAULT=nossl
DPX_CERT_DEFAULT=selfsigned
#DPX_CERT_DEFAULT=letsencrypt
endif
dpx-apigateway.env: 
	$(MAKE) set.apigateway.$(DPX_CERT_DEFAULT)

# nossl version config for the gateway
.PHONY: set.apigateway.nossl
set.apigateway.nossl: dpx-apigateway-nossl.env
	rm -rf dpx-vplugin-mgr-real.env
	$(MAKE) dpx-vplugin-mgr-real.env
	rm -rf dpx-vplugin-mgr-sim.env
	$(MAKE) dpx-vplugin-mgr-sim.env
	ln -sf $< dpx-apigateway.env
dpx-apigateway-nossl.env:
	echo "server_ssl_enabled=false" > $@
	echo "server_port=8085" >> $@
	echo "server_ssl_keyStoreType=" >> $@
	echo "server_ssl_key_store=" >> $@
	echo "server_ssl_key_alias=" >> $@
	echo "server_ssl_key_store_password=" >> $@

# selfsigned version config for the gateway
.PHONY: set.apigateway.selfsigned
set.apigateway.selfsigned: dpx-apigateway-selfsigned.env
	rm -rf dpx-vplugin-mgr-real.env
	$(MAKE) dpx-vplugin-mgr-real.env
	rm -rf dpx-vplugin-mgr-sim.env
	$(MAKE) dpx-vplugin-mgr-sim.env
	ln -sf $< dpx-apigateway.env
dpx-apigateway-selfsigned.env: certs-selfsigned
	echo "server_ssl_enabled=true" > $@
	echo "server_port=443" >> $@
	echo "server_ssl_key_store=/opt/keystore.jks" >> $@
	echo "server_ssl_keyStoreType=JKS" >> $@
	echo "server_ssl_key_alias=selfsigned" >> $@
	echo "server_ssl_key_store_password=$(SSL_CERT_PASS)" >> $@

certs-selfsigned:
	@echo '================ Inside selfsigned ============'
	mkdir -p $@
	cd $@; keytool -genkey -keyalg RSA -alias selfsigned -keystore keystore.jks -dname "CN=jwt, L=Brisbane, S=Brisbane, C=AU" -keypass $(SSL_CERT_PASS) -storepass $(SSL_CERT_PASS) -validity 360 -keysize 2048
	keytool -list -v -keystore $@/keystore.jks -alias selfsigned -storepass $(SSL_CERT_PASS) -keypass $(SSL_CERT_PASS) | sed -n 's/^[^:]*SHA1[^:]*:[[:blank:]]*//p' > $@/keystore.jks.thumbprint
	mkdir -p opt-apigateway
	cp $@/keystore.jks opt-apigateway
	cp $@/keystore.jks.thumbprint opt-apigateway
	@echo '====== Completed ======='

# letsencrypt version config for the gateway
.PHONY: set.apigateway.letsencrypt
set.apigateway.letsencrypt: dpx-apigateway-letsecrypt.env
	ln -sf $< dpx-apigateway.env
dpx-apigateway-letsecrypt.env: certs-letsencrypt
	echo "server_ssl_enabled=true" > $@
	echo "server_port=443" >> $@
	echo "server_ssl_key_store=/opt/keystore.p12" >> $@
	echo "server_ssl_keyStoreType=PKCS12" >> $@
	echo "server_ssl_key_alias=tomcat" >> $@
	echo "server_ssl_key_store_password=$(SSL_CERT_PASS)" >> $@

certs-letsencrypt:
	@echo '============ Inside lets-encrypt =========='
	$(call assert_macro,LETS_ENCRYPT_DOMAIN)
	$(call assert_macro,LETS_ENCRYPT_USER_EMAIL)
	git clone https://github.com/certbot/certbot
	cd certbot; ./certbot-auto certonly -a standalone --agree-tos --email $(LETS_ENCRYPT_USER_EMAIL) -d $(LETS_ENCRYPT_DOMAIN) -d www.$(LETS_ENCRYPT_DOMAIN)
	cd /etc/letsencrypt/live/$(LETS_ENCRYPT_DOMAIN); openssl pkcs12 -export -in fullchain.pem -inkey privkey.pem -out keystore.p12 -name tomcat -CAfile chain.pem -caname root
	cp /etc/letsencrypt/live/technicaltraining.online/keystore.p12 $@
	mkdir -p $@
	mkdir -p opt-apigateway
	cp $@/keystore.p12 opt-apigateway
	@echo '====== Completed ======='

#
# generate the keys for authentication
KEY_PASS = Catalogic123\#
SRC_KEY_PASS = -keypass $(KEY_PASS)
SRC_KEY_PASS2 = -srckeypass $(KEY_PASS)
SRC_STORE_PASS = -storepass $(KEY_PASS)
SRC_STORE_PASS2 = -srcstorepass $(KEY_PASS)
DST_KEY_PASS = -destkeypass $(KEY_PASS)
DST_STORE_PASS = -deststorepass $(KEY_PASS)
DST_STORE_PASS2 = -passin pass:$(KEY_PASS)
MY_STORE_PASS = -passout pass:$(KEY_PASS)
SSL_CERT_PASS = catalogic
keys:
	mkdir keys
	cd keys; keytool -genkeypair -alias jwt -keyalg RSA -dname "CN=jwt, L=Brisbane, S=Brisbane, C=AU" $(SRC_KEY_PASS) -keystore catalogic.jks $(SRC_STORE_PASS)
	cd keys; keytool -v -importkeystore -srckeystore catalogic.jks -srcalias jwt $(SRC_STORE_PASS2) $(SRC_KEY_PASS2) -destkeystore catalogic.p12 -destalias jwt $(DST_STORE_PASS) $(DST_KEY_PASS) -deststoretype PKCS12
	cd keys; openssl pkcs12 -in catalogic.p12 -out catalogic.pem $(DST_STORE_PASS2) $(MY_STORE_PASS)
	cd keys; openssl rsa -in catalogic.pem -pubout -out catalogic.pub $(DST_STORE_PASS2)

opt: opt-auth opt-apigateway

opt-auth: keys
	mkdir opt-auth
	cp keys/catalogic.jks opt-auth
	
opt-apigateway: keys
	mkdir -p opt-apigateway
	grep -v '\-\-\-\-\-' keys/catalogic.pub > opt-apigateway/catalogic.pub

stack-logs:
	mkdir stack-logs
	chmod 777 stack-logs

plugins:
	mkdir plugins

#
# --- USEFUL TARGETS FOR DEV/TEST ---
# 
# master server in a container 
# tag for the DPX MS to use
CATALOGIC_DPX_MS_TAG = 232

start-ms:
	$(DOCKER) run -d --rm -p 6123:6123 joylogics/catalogic-dpx-ms:$(CATALOGIC_DPX_MS_TAG)> catalogic-dpx-ms.id

stop-ms: catalogic-dpx-ms.id
	$(DOCKER) stop $(shell cat catalogic-dpx-ms.id)
	rm -rf catalogic-dpx-ms.id

#
# syncui - commandline tool to directly conect to DPX master
#
syncui:
	$(DOCKER) run --rm --net=host -e SSPRODIR=/opt/DPX --entrypoint /opt/DPX/bin/syncui -it joylogics/catalogic-dpx-ms:$(CATALOGIC_DPX_MS_TAG)

#
# pick up the authentication token from the local file, auth_token
AUTH_TOKEN=$(shell cat auth_token)

# auth_token is 'built' by executing a login curl, then using jq to to parse out the 'token' element
# if it's not there, a login is needed
auth_token:
	@echo "you must login first"; exit -1

# utility target to login and save auth_token
login: t.vpmgr.login 

logout:
	rm -rf auth_token
#
# tests for authentication service 
#
ifdef SKIP_ZUUL
SVC_AUTH=https://$(THIS_HOST):8081
else
SVC_AUTH=https://$(THIS_HOST)/auth
endif
DPX_USERNAME=sysadmin
DPX_PASSWORD=sysadmin
t.auth.login:
	$(CURL) \
		-X POST $(SVC_AUTH)/login \
		-H 'cache-control: no-cache' \
		-H 'content-type: application/json' \
		-d '{"username":"$(DPX_USERNAME)","password":"$(DPX_PASSWORD)"}' \
		$(JQ)
	jq -r '("Bearer " + .token)' < out.json > auth_token

#
# tests for rest service 
#
ifdef SKIP_ZUUL
SVC_REST=https://$(THIS_HOST):8080
else
SVC_REST=https://$(THIS_HOST)/app
endif
t.rest.get.policies: auth_token
	$(CURL) \
		-X GET $(SVC_REST)/api/policies \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H 'accept: application/json' \
		$(JQ)

REST_NODEGROUP_NAME=test-group
t.rest.post.node_groups: auth_token
	$(call assert_macro,REST_NODEGROUP_NAME)
	$(CURL) \
		-X POST $(SVC_REST)/api/node_groups \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H 'content-type: application/json' \
		-d '{"admin_name":"$(DPX_USERNAME)","comment":"","node_group_name":"$(REST_NODEGROUP_NAME)"}' \
		$(JQ)

t.rest.get.node_groups: auth_token
	$(CURL) \
		-X GET $(SVC_REST)/api/node_groups \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H 'content-type: application/json' \
		$(JQ)

REST_NODE_NAME=test-node
t.rest.post.nodes: auth_token
	$(call assert_macro,REST_NODE_NAME)
	$(CURL) \
		-X POST $(SVC_REST)/api/nodes \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H 'content-type: application/json' \
		-d '{"admin_name":"$(DPX_USERNAME)","comment":"","node_group_name":"$(REST_NODEGROUP_NAME)","node_name":"$(REST_NODE_NAME)"}' \
		$(JQ)

t.rest.get.nodes: auth_token
	$(CURL) \
		-X GET $(SVC_REST)/api/nodes \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H 'content-type: application/json' \
		$(JQ)

REST_VCENTER_ID=vcenter_test
REST_VCENTER_HOST=vcenter_test_host
REST_VCENTER_USERNAME=vcenter_test_username
REST_VCENTER_PASSWORD=vcenter_test_password
t.rest.post.vcenters: auth_token
	$(call assert_macro,REST_VCENTER_ID)
	$(call assert_macro,REST_VCENTER_HOST)
	$(call assert_macro,REST_VCENTER_USERNAME)
	$(call assert_macro,REST_VCENTER_PASSWORD)
	$(CURL) \
		-X POST $(SVC_REST)/api/vcenters \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H 'content-type: application/json' \
		-d '{"node_group_name":"$(REST_NODEGROUP_NAME)","node_name":"$(REST_VCENTER_ID)","comment":"","hostname":"$(REST_VCENTER_HOST)","username":"$(REST_VCENTER_USERNAME)","password":"$(REST_VCENTER_PASSWORD)"}' \
		$(JQ)

ifndef REST_VCENTER_SECRET
REST_VCENTER_SECRET=?password_key=foobar
endif
t.rest.get.vcenters: auth_token
	$(CURL) \
		-X GET $(SVC_REST)/api/vcenters$(REST_VCENTER_SECRET) \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H 'content-type: application/json' \
		$(JQ)

t.rest.get.vmobjects: auth_token
	$(call assert_macro,REST_VCENTER_ID)
	$(CURL) \
		-X GET $(SVC_REST)/api/vcenters/$(REST_VCENTER_ID)/vmobjects \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H  "accept: application/json" \
		$(JQ)

t.rest.patch.vmobjects: auth_token
	$(call assert_macro,REST_VCENTER_ID)
	$(call assert_macro,REST_POLICY_NAME)
	$(call assert_macro,REST_OBJECT_ID)
	$(call assert_macro,REST_SRC_PATH)
	$(CURL) \
		-X PATCH $(SVC_REST)/api/vcenters/$(REST_VCENTER_ID)/vmobjects \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H "accept: application/json" \
		-H "Content-Type: application/json" \
		-d '[ { "policy_name": "$(REST_POLICY_NAME)", "object_id": "$(REST_OBJECT_ID)", "src_path": "$(REST_SRC_PATH)" }]'


#
# tests for vplugin manager service 
#
ifdef SKIP_ZUUL
SVC_VPMGR=https://$(THIS_HOST):8082
else
SVC_VPMGR=https://$(THIS_HOST)/plugin-mgr
endif
DPX_MASTER_IP=$(THIS_HOST)
t.vpmgr.login:
	$(call assert_macro,DPX_USERNAME)
	$(call assert_macro,DPX_PASSWORD)
	$(call assert_macro,DPX_MASTER_IP)
	$(CURL) \
		-X POST $(SVC_VPMGR)/api/users/login \
		-H 'cache-control: no-cache' \
		-H 'content-type: application/json' \
		-c cookies.txt \
		-d '{"username":"$(DPX_USERNAME)","password":"$(DPX_PASSWORD)","dpx_master_ip":"$(DPX_MASTER_IP)"}' \
		$(JQ)
	jq -r '("Bearer " + .token)' < out.json > auth_token

t.vpmgr.put.config: auth_token
	$(CURL) \
		-X PUT $(SVC_VPMGR)/api/config \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H 'cache-control: no-cache' \
		-H 'content-type: application/json' \
		-d '{"dpx_plugin_repo_url" : "https://s3.amazonaws.com/jl-dpx-plugin-repo/dpx_plugins.json","vcenter_server_repo_url" : "https://s3.amazonaws.com/jl-dpx-plugin-repo/vcenter-servers.json"}' \
		$(JQ)

t.vpmgr.get.config: auth_token
	$(CURL) \
		-X GET $(SVC_VPMGR)/api/config \
		-H 'Authorization: $(AUTH_TOKEN)' \
		$(JQ)

t.vpmgr.get.dpx_plugins: auth_token
	$(CURL) \
		-X GET $(SVC_VPMGR)/api/dpx_plugins \
		-H 'Authorization: $(AUTH_TOKEN)' \
		$(JQ)

t.vpmgr.get.vcenters: auth_token
	$(CURL) \
		-X GET $(SVC_VPMGR)/api/vcenters \
		-H 'Authorization: $(AUTH_TOKEN)' \
		$(JQ)

t.vpmgr.get.vcenter.dpx_plugins: auth_token
	$(call assert_macro,VPMGR_VCENTER_ID)
	$(CURL) \
		-X GET $(SVC_VPMGR)/api/vcenters/$(VPMGR_VCENTER_ID)/dpx_plugins?refreshState=true \
		-H 'Authorization: $(AUTH_TOKEN)' \
		$(JQ)

t.vpmgr.patch.vcenter.dpx_plugins.install: auth_token
	$(call assert_macro,VPMGR_VCENTER_ID)
	$(call assert_macro,VPLUGIN_VER)
	$(CURL) \
		-X PATCH $(SVC_VPMGR)/api/vcenters/$(VPMGR_VCENTER_ID)/dpx_plugins \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H "Content-Type: application/json" \
		-b cookies.txt \
		-d '{"desiredState": "INSTALLED","desiredVersion": "$(VPLUGIN_VER)"}' \
		$(JQ)

t.vpmgr.patch.vcenter.dpx_plugins.uninstall: auth_token
	$(call assert_macro,VPMGR_VCENTER_ID)
	$(CURL) \
		-X PATCH $(SVC_VPMGR)/api/vcenters/$(VPMGR_VCENTER_ID)/dpx_plugins \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H "Content-Type: application/json" \
		-b cookies.txt \
		-d '{"desiredState": "UNINSTALLED"}' \
		$(JQ)
