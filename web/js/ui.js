// Njiwa UI control stuff
// (c) Digital Solutions


String.prototype.toTitleCase = function () {
    return this.replace(/\w\S*/g, function (txt) {
        return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();
    });
};


function getfupload(item_id)
{
    try {
        return window.fileuploads[item_id];
    }  catch(e) {

    }
    return null;
}

function info_display(el, level, message) {
    var status_class = 'alert ';
    var status_icon = 'fas ';
    switch (level) {
        case 'error':
        case 'fail':
        case 'exception':
            status_class += ' alert-danger';
            status_icon += 'fa-exclamation-circle';
            break;
        case 'warn':
        case 'warning':
            status_class += ' alert-warning';
            status_icon += 'fa-exclamation-circle';
            break;
        case 'ok':
        case 'pass':
        case 'success':
            status_class += ' alert-success';
            status_icon += 'fa-check-circle';
            break;
        default:
        case 'info':
            status_class += ' alert-info';
            status_icon += 'fa-info';
            break;
    }

    var icon_el = $('<span>', {'class': status_icon});
    var message_el = $('<span>').html(message);

    $(el).empty();
    if (message) {
        $(el).attr({
            'class': status_class
        }).append(icon_el)
                .append(' ')
                .append(message_el);
    } else {
        $(el).removeClassPrefix('alert');
    }
}


$(document).ready(function () {

    var body = $('body');
    body.on('click', '.jumper', function () {
        var url = $(this).data('url');
        var div = $(this).data('div') || 'main';

        $('#' + div).load(url + '.html');
        return false;
    });

    // Handle file uploads
    body.on('change', 'input[type=file].fileupload', function () {
        var input = $(this);
        var resType = $(input).data('result') || 'url';
        var item_id = input.prop('id') || input.prop('name');
        var dataValidator = input.data('uploadvalidator');
        var fR = new FileReader();
        window.fileuploads = window.fileuploads || {};
        fR.onload = function () {
            var data = fR.result;
            window.fileuploads[item_id] = data;

            console.log('Read data for as ' + (resType === 'url' ? 'data URL' : 'text') + ' #' + item_id + ', with' + ' length: ' + (data || '').length);
            console.log(data);
            try {
                // Run validator
                var fn = window[dataValidator];
                fn(item_id, data);
            } catch (e) {
            }
        };
        if (resType === 'url') fR.readAsDataURL($(input).prop('files')[0]); else fR.readAsText($(input).prop('files')[0]);

    });


    // Add validator methods
    $.validator.addMethod('oid', function (v,el) {
        if (v)
            return true;
        var re = new RegExp('^[1-9]+([.][0-9]+)*$');
        if (!re.test(v))
            return  false;
        else
        return true;
    }, 'Please enter a valid OID, e.g. 1.2.3.4');

    $.validator.addMethod('iin', function (v,el) {
        if (v)
            return true;
        var re = new RegExp('^[1-9][0-9]{15,19}$');
        if (!re.test(v))
            return  false;
        else
            return true;
    }, 'Please enter a valid IIN, e.g. 112345123452323');
});