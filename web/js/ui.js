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

function info_display(el, level, message, after_fn) {
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
       setTimeout(function () { // Clear after a wait period
           $(el).empty();
           $(el).removeClassPrefix('alert');
           if ($.isFunction(after_fn))
               after_fn();
       }, 2000) ;
    } else {
        $(el).removeClassPrefix('alert');
    }
}


$(document).ready(function () {


    $.fn.removeClassPrefix = function (prefix) {

        this.each(function (i, it) {
            var classes = it.className.split(" ")
                    .map(function (item) {
                        return item.indexOf(prefix) === 0 ? "" : item;
                    });
            //it.className = classes.join(" ");
            it.className = $.trim(classes.join(" "));

        });

        return this;
    };

    var body = $('body');
    body.on('click', '.jumper', function () {
        var url = $(this).data('url');
        var div = $(this).data('div') || 'main';
        var link_id = $(this).attr('id');
        localStorage.lastlink = JSON.stringify(link_id); // Keep it

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
        // See https://www.regextester.com/96618
        var re = new RegExp('^([1-9][0-9]{0,3}|0)(\\.([1-9][0-9]{0,3}|0)){5,13}$');
        if (!re.test(v))
            return  false;
        else
        return true;
    }, 'Please enter a valid OID, e.g. 1.2.3.4....');

    $.validator.addMethod('iin', function (v,el) {
        if (v)
            return true;
        // See https://stackoverflow.com/questions/27796688/regular-expression-for-all-bank-card-numbers
        var re = new RegExp('^[1-9][0-9]{15,19}$');
        if (!re.test(v))
            return  false;
        else
            return true;
    }, 'Please enter a valid IIN, e.g. 112345123452323');
});