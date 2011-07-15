

function addHostName() {

    if ( !allHostsFilled() ) return;
    var id=findNextHostName();

    var content="<p>" + 
        "<label id='label" + id + "'>host" + id + "</label>" + 
        "<input id='settings_host" + id + "' name='settings[host" + id + "]' size='40' type='text' value='' onkeyup='checkAddHostState()'/> " + 
        getRemoveNode(id) + 
    "</p>";

    var values=getHostValues();
    if (id==1) addFirstRemoveNode();

    getHostsNode().innerHTML += content;
    setHostValues(values);

    $get("addhost").disabled=true;
    
}

function checkAddHostState(){
    var btaddhost=$get('addhost');
    if ( allHostsFilled() ) btaddhost.disabled=false;
    else btaddhost.disabled=true;
}

function getRemoveNode(id) {
    return "<span style='color:blue;text-decoration:underline;cursor:pointer' id='remove" + id + "' onclick='removeHostName(this)'>Remove</span>";
}

function addFirstRemoveNode() {
    $get('settings_host0').parentNode.innerHTML += getRemoveNode(0);
}

function removeHostName(node) {
    item=node.parentNode;
    getHostsNode().removeChild(item);

    // gather remaining nodes and re number host names
    // that will keep the settings array tight
    var maxhost=100;

    var node=0;
    var id=0;
    while(node <= maxhost) {
        var item=$get('settings_host'+node);
        if (item) {
            item.id='settings_host'+id;
            item.name='settings[host'+id+']';

            var label=$get('label'+node);
            label.innerHTML="host"+id;
            label.id='label'+id;

            var remove=$get('remove'+node);
            remove.id='remove'+id;

            id++;
        }
        node++
    }

    if (id==1) {
        var remove=$get('remove0');
        remove.parentNode.removeChild(remove);
    }

    if ( $get('addhost').disabled ) checkAddHostState();
}


function setHostValues(values) {
    for (var item in values) $get(item).value=values[item]
}

function getHostValues() {
    var returns={}
    var node=0;
    var display="";
    while(1) {
        var hostItem=$get('settings_host'+node);
        if (!hostItem) break;
        returns['settings_host'+node]=hostItem.value;
        node++;
    }

    return returns;
}

function getHostsNode() { return $get('hostItems'); }

function findNextHostName() {
    var node=0;

    while(1) {
        var hostItem=$get('settings_host'+node);
        if (!hostItem) return node;
        node++;
    }
}

function allHostsFilled() {
    var node=0;
    while(1) {
        var host=$get('settings_host'+node);
        if(host) {
            if (trimValue(host.value)=="" || host.value==null) return false;
        } else break;
        node++;
    }
    return true;
}

function trimValue(value) {
    value = new String(value).replace(/^\s+|\s+$/, "");
    return value;
}

function check_recommended_port() {
    $get('settings_port').disabled=$get('settings_use_recommended_port').checked;
}

function $get(id) { return document.getElementById(id); }
