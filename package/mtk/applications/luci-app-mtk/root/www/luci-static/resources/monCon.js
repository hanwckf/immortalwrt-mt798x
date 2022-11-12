
MonCon = function()
{

    this.conOk = function()
    {
        window.setTimeout(MonCon.ping, 5000);
    }

    this.ping = function()
    {
        var img = document.createElement('img');
        img.onload = this.conOk;
        img.onerror = this.conErr;
        img.src = '/luci-static/resources/icons/loading.gif?' + Math.random();
    }

    this.conErr = function()
    {
        alert('Device unreachable!');
        window.location.reload(true);
    }

}
MonCon.ping = function()
{
    (new MonCon()).ping();
}
