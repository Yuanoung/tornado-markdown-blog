!function (i) {
    var c, e, a, s, d, n, u;
    d = [], c = {
        SERVER_PV_URL: "https://pv.csdn.net/csdnbi",
        SERVER_RE_URL: "https://re.csdn.net/csdnbi",
        DELAY: 500,
        DEBUG: !0
    }, s = {PV: "pv", VIEW: "view", CLICK: "click"}, u = {SKIPPED_AND_VISIBLE: "0", VISIBLE: "1"}, a = {
        getCookie: function (e) {
            var t, r = new RegExp("(^| )" + e + "=([^;]*)(;|$)");
            return (t = document.cookie.match(r)) ? unescape(t[2]) : null
        }, buildRequestData: function (e, t) {
            return s.PV == e ? {
                headers: {component: "enterprise", datatype: "track", version: "v1"},
                body: JSON.stringify({re: i.param(t)})
            } : {
                headers: {component: "enterprise", datatype: "re", version: "v1"},
                body: JSON.stringify({re: i.param(t)})
            }
        }, serverUrl: function (e) {
            return s == e ? c.SERVER_PV_URL : c.SERVER_RE_URL
        }, initData: function () {
            var e, t;
            return n = {
                uid: (null != (e = /(; )?(UserName|_javaeye_cookie_id_)=([^;]+)/.exec(window.document.cookie)) ? e[3] : void 0) || "-",
                ref: window.document.referrer,
                pid: window.location.host.split(".csdn.net")[0],
                mod: "",
                con: "",
                ck: "-",
                curl: window.location.href,
                session_id: a.getCookie("dc_session_id"),
                cfg: {viewStrategy: u.VISIBLE}
            }, i("meta[name=track]").attr("content") && (t = JSON.parse(i("meta[name=track]").attr("content"))), t && (n = i.extend({}, n, t)), n
        }, tos: function () {
            var e, t, r, o;
            e = +new Date / 1e3 | 0, r = null != (t = /\bdc_tos=([^;]*)(?:$|;)/.exec(document.cookie)) ? t[1] : void 0;
            try {
                o = e - parseInt(r, 36)
            } catch (e) {
                console.warn("tos init error", e), o = -1
            }
            return document.cookie = "dc_tos=" + e.toString(36) + " ; expires=" + new Date(1e3 * (e + 14400)).toGMTString() + " ; max-age=14400 ; path=/ ; domain=." + this.topDomain(window.location.host), o
        }, topDomain: function (e) {
            return /\.?([a-z0-9\-]+\.[a-z0-9\-]+)(:\d+)?$/.exec(e)[1]
        }, copyArr: function (e) {
            for (var t = [], r = 0; r < e.length; r++) t.push(e[r]);
            return t
        }, isView: function (e, t) {
            var r = this;
            if (!e) return !1;
            var o = this.getElementBottom(e), n = o + e.offsetHeight;
            return u.VISIBLE == t ? r.scrollTop() < o && o < r.scrollTop() + r.windowHeight() || r.scrollTop() < n && n < r.scrollTop() + r.windowHeight() : u.SKIPPED_AND_VISIBLE == t ? o <= r.scrollTop() + r.windowHeight() || (r.scrollTop() < o && o < r.scrollTop() + r.windowHeight() || r.scrollTop() < n && n < r.scrollTop() + r.windowHeight()) : void 0
        }, scrollTop: function () {
            return Math.max(document.body.scrollTop, document.documentElement.scrollTop)
        }, windowHeight: function () {
            return "CSS1Compat" == document.compatMode ? document.documentElement.clientHeight : document.body.clientHeight
        }, getElementTop: function (e) {
            if ("undefined" != typeof jQuery) return i(e).offset().top;
            var t = e.offsetTop;
            for (e = e.offsetParent; null != e;) t += e.offsetTop, e = e.offsetParent;
            return t
        }, getElementBottom: function (e) {
            if ("undefined" != typeof jQuery) return i(e).offset().top + i(e).height();
            var t = e.offsetTop;
            for (e = e.offsetParent; null != e;) t += e.offsetTop, e = e.offsetParent;
            return t
        }, url2Obj: function (e) {
            var t = {}, r = e.split("&");
            for (var o in r) t[r[o].split("=")[0]] = decodeURIComponent(r[o].split("=")[1]);
            return t
        }, fixParamConTop: function (e, t) {
            return -1 < e.con.split(",top_") || (e.con = e.con + ",top_" + i(t).offset().top), e
        }
    }, e = {
        timer: 0, checkTimer: 0, reportServer: function (e, t) {
            if (void 0 !== e && void 0 !== t) {
                var r = a.buildRequestData(e, t);
                d.push(r)
            }
            var o = a.copyArr(d);
            d = [];
            var n = s.PV == e ? c.SERVER_PV_URL : c.SERVER_RE_URL;
            i.ajax({
                url: n,
                type: "POST",
                crossDomain: !0,
                xhrFields: {withCredentials: !0},
                contentType: "text/plain;charset=UTF-8",
                data: JSON.stringify(o),
                success: function () {
                },
                error: function () {
                    console.error("csdn.track.reportServer()", arguments)
                }
            })
        }, reportServerDelay: function (e, t) {
            var r = a.buildRequestData(e, t);
            d.push(r);
            var o = this;
            o.timer && clearTimeout(o.timer), o.timer = setTimeout(function () {
                o.reportServer()
            }, c.DELAY)
        }, reportView: function (e, t, r) {
            e = a.fixParamConTop(e, t);
            var o = i.extend(!0, {}, n, e);
            o.ck = "-", delete o.cfg, o.type = s.VIEW, void 0 === r ? this.reportServerDelay(s.VIEW, o) : this.reportServer(s.VIEW, o), "function" == typeof csdn.afterTrackReportView && csdn.afterTrackReportView(t, e)
        }, reportClick: function (e, t) {
            e = a.fixParamConTop(e, t);
            var r = i.extend(!0, {}, n, e);
            r.ck = r.con, delete r.cfg, r.type = s.CLICK, this.reportServer(s.CLICK, r)
        }, reportPageView: function (e) {
            var t = i.extend(!0, {}, n, e);
            t.tos = a.tos(), t.referrer = t.ref, t.user_name = t.uid, t.ref = "", t.uid = "", delete t.cfg, t.type = s.PV, this.reportServer(s.PV, t)
        }, viewCheck: function () {
            clearTimeout(this.checkTimer), this.checkTimer = setTimeout(function () {
                i("[data-track-view]").each(function () {
                    var e = i(this), t = i.extend({}, n, e.data("trackView"));
                    a.isView(e.get(0), t.cfg.viewStrategy) && (csdn.track.reportView(t, this), e.removeData("trackView"), e.removeAttr("data-track-view"))
                })
            }, 200)
        }, isView: function (e) {
            return a.isView(e)
        }, debug: function (e, t) {
            var r, o;
            for (var n in e) o = e[n], r = a.url2Obj(JSON.parse(o.body).re), void 0 !== t ? console.log(r.type, "--\x3e:", o.headers.datatype, r.mod, r.con) : console.log(r.type, "--\x3e:", r)
        }
    }, void 0 === window.csdn && (window.csdn = {}), window.csdn.track = e, (n = a.initData()).disabled || csdn.track.reportPageView()
}(jQuery), jQuery(function () {
    var t = csdn.track;
    jQuery(document).on("click", "[data-track-click]", function () {
        var e = jQuery(this).data("trackClick");
        t.reportClick(e, this)
    }), t.viewCheck(jQuery("[data-track-view]")), jQuery(window).on("scroll", function () {
        t.viewCheck(jQuery("[data-track-view]"))
    })
});