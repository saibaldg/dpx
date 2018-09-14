#
# Makefile for running some integration tests on catalogic-dpx 

#
#default target
all: 
	@echo 'available targets:'
	@echo '	== environment related =='
	@echo '	start - bring up the stack \"dpx\"'
	@echo '	status - show status of the stack \"dpx\"'
	@echo '	stop - bring down the stack \"dpx\"'
	@echo '	clean - clean up the environment'
	@echo '	== to login to dpx and save the authentication token in the local file =='
	@echo '	login'
	@echo '	== some tests on the rest svc =='
	@echo '	t.rest.get.policies - list policies'
	@echo '	t.rest.get.nodes - list nodes'
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

# choose docker execution
DOCKER=docker
#DOCKER=sudo docker

# choose curl execution
CURL=curl
#CURL=curl -v

# post-curl processing.
# following uses jq to prettify the output and save a copy in a local file: out.json
JQ=| jq . | tee out.json

#
# pick up the authentication token from the local file, auth_token
AUTH_TOKEN=$(shell cat auth_token)

# auth_token can be 'build' by executing a login curl, then using jq to to parse out the 'token' element
auth_token:
	jq -r '("Bearer " + .token)' < out.json > auth_token

# utility target to login and save auth_token
login: t.vpmgr.login 
	jq -r '("Bearer " + .token)' < out.json > auth_token

# dpx.env contains the local ip address
dpx.env:
	hostname -I | awk '{print "DPX_MASTER_HOST="$$1}' > dpx.env
	hostname -I | awk '{print "DOCKER_HOST_IP="$$1}' >> dpx.env

#
# bring up the stack
start: opt keys rest-logs dpx.env
	$(DOCKER) stack deploy -c docker-compose.yml dpx --with-registry-auth

# check the status of the stack
status:
	$(DOCKER) stack services dpx

# bring down the stack
stop:
	$(DOCKER) stack rm dpx

# clean up
clean: stop
	rm -rf keys opt-auth opt-apigateway rest-logs auth_token cookies.txt out.json dpx.env


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
	mkdir opt-apigateway
	grep -v '\-\-\-\-\-' keys/catalogic.pub > opt-apigateway/catalogic.pub

rest-logs:
	mkdir rest-logs


#
# tests for authentication service 
#
#SVC_AUTH=http://127.0.0.1:8081
SVC_AUTH=http://127.0.0.1:8085/auth
DPX_USERNAME=sysadmin
DPX_PASSWORD=jldpx1p
t.auth.login:
	$(CURL) \
		-X POST $(SVC_AUTH)/login \
		-H 'cache-control: no-cache' \
		-H 'content-type: application/json' \
		-d '{"username":"$(DPX_USERNAME)","password":"$(DPX_PASSWORD)"}' \
		$(JQ)

#
# tests for rest service 
#
#SVC_REST=http://127.0.0.1:8080
SVC_REST=http://127.0.0.1:8085/app
t.rest.get.policies: auth_token
	$(CURL) \
		-X GET $(SVC_REST)/api/policies \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H 'accept: application/json' \
		$(JQ)

t.rest.get.nodes: auth_token
	$(CURL) \
		-X GET $(SVC_REST)/api/nodes \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H 'content-type: application/json' \
		$(JQ)

t.rest.get.vcenters: auth_token
	$(CURL) \
		-X GET $(SVC_REST)/api/vcenters \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H 'content-type: application/json' \
		$(JQ)

REST_VCENTER_ID=vcenter512
t.rest.get.vmobjects: auth_token
	$(CURL) \
		-X GET $(SVC_REST)/api/vcenters/$(REST_VCENTER_ID)/vmobjects \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H  "accept: application/json" \
		$(JQ)

REST_POLICY_NAME=bastion1-bak-226
REST_OBJECT_ID=5029d4be-9c23-e5e9-7044-9d4dac632708
t.rest.patch.vmobjects: auth_token
	$(CURL) \
		-X PATCH $(SVC_REST)/api/vcenters/$(REST_VCENTER_ID)/vmobjects \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H "accept: application/json" \
		-H "Content-Type: application/json" \
		-d '[ { "policy_name": "$(REST_POLCY_NAME)", "object_id": "$(REST_OBJECT_ID)" }]'

#
# tests for vplugin manager service 
#
SVC_VPMGR=http://127.0.0.1:8082
#SVC_VPMGR=http://127.0.0.1:8085/plugin-mgr
DPX_MASTER_IP=10.5.5.12
t.vpmgr.login:
	$(CURL) \
		-X POST $(SVC_VPMGR)/api/users/login \
		-H 'cache-control: no-cache' \
		-H 'content-type: application/json' \
		-c cookies.txt \
		-d '{"username":"$(DPX_USERNAME)","password":"$(DPX_PASSWORD)","dpx_master_ip":"$(DPX_MASTER_IP)"}' \
		$(JQ)

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

VPMGR_VCENTER_ID=3
t.vpmgr.get.vcenter.dpx_plugins: auth_token
	$(CURL) \
		-X GET $(SVC_VPMGR)/api/vcenters/$(VPMGR_VCENTER_ID)/dpx_plugins?refreshState=true \
		-H 'Authorization: $(AUTH_TOKEN)' \
		$(JQ)

VPLUGIN_VER=2.0.2
t.vpmgr.patch.vcenter.dpx_plugins.install: auth_token
	$(CURL) \
		-X PATCH $(SVC_VPMGR)/api/vcenters/$(VPMGR_VCENTER_ID)/dpx_plugins \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H "Content-Type: application/json" \
		-b cookies.txt \
		-d '{"desiredState": "INSTALLED","desiredVersion": "$(VPLUGIN_VER)"}' \
		$(JQ)

t.vpmgr.patch.vcenter.dpx_plugins.uninstall: auth_token
	$(CURL) \
		-X PATCH $(SVC_VPMGR)/api/vcenters/$(VPMGR_VCENTER_ID)/dpx_plugins \
		-H 'Authorization: $(AUTH_TOKEN)' \
		-H "Content-Type: application/json" \
		-d '{"desiredState": "UNINSTALLED"}' \
		$(JQ)

