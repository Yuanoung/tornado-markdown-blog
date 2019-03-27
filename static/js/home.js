$().ready(function () {
    $(window).scroll(function () {
        if ($(window).scrollTop() + $(window).height() == $(document).height()) {
            var page = $("input[name='_next_url']").val();
            $.get(("/?page=" + $("input[name='_next_url']").val()),
                function (data) {
                    if (data) {
                        $(".post-feed").append(data);
                        $("input[name='_next_url']").val(parseInt(page) + 1);
                    }
                })
        }
    });

});