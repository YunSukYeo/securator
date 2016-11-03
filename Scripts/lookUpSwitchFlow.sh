if [ "$#" -lt 1 ] 
	then
		echo "Usage: ./lookUpSwitchFlowRules.sh [switch number]"
		exit 1
fi

wget http://127.0.0.1:8181/restconf/operational/opendaylight-inventory:nodes/node/openflow:$1/table/0/ --password=admin --user=admin
