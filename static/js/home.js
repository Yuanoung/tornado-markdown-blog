$().ready(function () {
    var stop_scroll = false;
    $(window).scroll(function () {
        if (!stop_scroll && $(window).scrollTop() + $(window).height() + .5 >= $(document).height()) {
            var page = $("input[name='_next_url']").val();
            $.get(("/?page=" + page),
                function (data) {
                    if (data) {
                        $(".post-feed").append(data);
                        $("input[name='_next_url']").val(parseInt(page) + 1);
                    } else
                        stop_scroll = true;
                })
        }
    });

});