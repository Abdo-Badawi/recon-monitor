// Live event/job feed via Django Channels WebSocket. Prepends to #live-feed if present.
(function () {
  var dot = document.getElementById("live-dot");
  function connect(path) {
    var proto = location.protocol === "https:" ? "wss" : "ws";
    var ws = new WebSocket(proto + "://" + location.host + path);
    ws.onopen = function () { if (dot) dot.classList.remove("off"); };
    ws.onclose = function () { if (dot) dot.classList.add("off"); setTimeout(function(){connect(path);}, 5000); };
    ws.onmessage = function (ev) {
      try {
        var d = JSON.parse(ev.data);
        var feed = document.getElementById("live-feed");
        if (feed) {
          var div = document.createElement("div");
          div.className = "ev";
          var label = d.event_type || d.type || "event";
          var asset = d.asset_value || d.job_type || "";
          div.innerHTML = "<span class='badge b-" + (d.severity || d.status || "INFO") + "'>" + label + "</span> " + asset;
          feed.prepend(div);
        }
      } catch (e) {}
    };
  }
  connect("/ws/events/");
})();
