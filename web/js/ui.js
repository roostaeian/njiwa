// Njiwa UI control stuff
// (c) Digital Solutions


$(document).ready(function () {

    $('body').on('click', '.jumper', function () {
        var url = $(this).data('url');
        var div = $(this).data('div') || 'main';

        $('#' + div).load(url + '.html');
        return false;
    });
});