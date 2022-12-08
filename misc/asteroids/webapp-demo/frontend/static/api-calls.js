var formatter = new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
  });

function removeAllChildNodes(parent) {
    while (parent.firstChild) {
        parent.removeChild(parent.firstChild);
    }
}

function updateDebtData() {
    const url = 'https://api.coincap.io/v2/rates/bitcoin'
    fetch(url, {
        method: 'GET',
        // mode: 'cors'
    })
        .then(response => response.json())
        .then(data => document.getElementById("bonus").innerHTML = formatter.format(data.data.rateUsd))
}

function getEnvInfo() {
    const url = 'http://' + window.location.hostname + ':5000/env'
    fetch(url, {
        method: 'GET',
    })
        .then(response => response.json())
        .then(data => updateEnvList(data))
}

function updateEnvList(dict) {
    list = document.getElementById("env")
    // clear the list before we do anything else
    removeAllChildNodes(list)
    for (const [key,value] of Object.entries(dict)) {
        var item = document.createElement('li');
        item.appendChild(document.createTextNode(key + '=' + value));
        list.appendChild(item);
    }
}

function getConfInfo() {
    const url = 'http://' + window.location.hostname + ':5000/config'
    fetch(url, {
        method: 'GET',
    })
        .then(response => response.json())
        .then(data => updateConfigList(data["configs"]))
}

function updateConfigList(array) {
    list = document.getElementById("config")
    // clear the list before we do anything else
    removeAllChildNodes(list)
    for (let i = 0; i < array.length; i++) {
        var item = document.createElement('li');
        item.appendChild(document.createTextNode(array[i]));
        list.appendChild(item);
    }
}


updateDebtData()
getEnvInfo()
getConfInfo()
