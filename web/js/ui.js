/*
 * Njiwa Open Source Embedded M2M UICC Remote Subscription Manager
 *
 *
 * Copyright (C) 2019 - , Digital Solutions Ltd. - http://www.dsmagic.com
 *
 * Njiwa Dev <dev@njiwa.io>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License.
 */

String.prototype.toTitleCase = function () {
    return this.replace(/\w\S*/g, function (txt) {
        return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();
    });
};

const fileUploadKey = 'fileupload';
function getfupload(item_id)
{
    try {
        return  $(item_id).data(fileUploadKey);
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
function ll(txt) {
    // reduce length
    if (txt.length > 16)
        return $('<span/>', {title: txt}).append(txt.substring(0, 16) + '...');
    else
        return txt;
}
function validateCert(item_id, data, fname) {
    var el = $('label[for="'+item_id+'"]');
    return $.ajax('rest/settings/validatecert',
        {
            method: 'POST',
            dataType: 'JSON',
            data: data,
            success: function(res) {
                $(el).empty();
                if (typeof  res === 'object')
                    $(el)
                    .append($('<span/>', {class:'text-info'})
                    .append(ll(res.subject + ', Serial #: ' +res.serialNumber + ' <' + fname.name+ '>')));
                else
                    $(el)
                    .append($('<span/>', {class:'text-warning'})
                    .append('Invalid certificate'));
            },
            error: function(status,data) {
                $(el)
                .empty()
                .append($('<span/>', {class:'text-warning'})
                .append('Invalid certificate! Choose file...'));
            }
        }

    );
}

function defaultFileValidator(item_id, data, fname) {
    // Simply put the name in...
    var el = $('label[for="'+item_id+'"]');
    $(el)
    .empty()
    .append($('<span/>', {class:'text-dark'})
        .append(fname.name));
}

function validateHex(data, item_id, fname) {
    // do nothing for now.
    return true;
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

        $('#' + div).load(url + '.display.html');
        return false;
    })
    // Handle file uploads
    .on('change', 'input[type=file][data-uploadvalidator]', function () {
        var input = $(this);
        var resType = $(input).data('result') || 'url';
        var item_id = input.prop('id') || input.prop('name');
        var dataValidator = input.data('uploadvalidator');
        var fname = $(input).prop('files')[0];
        var fR = new FileReader();

        fR.onload = function () {
            var data = fR.result;
            $(input).data(window.fileuploadKey,data);

            console.log('Read data for as ' + (resType === 'url' ? 'data URL' : 'text') + ' #' + item_id + ', with' + ' length: ' + (data || '').length);
            console.log(data);
            try {
                // Run validator
                var fn = window[dataValidator] || defaultFileValidator;
                fn(item_id, data, fname);
            } catch (e) {
            }
        };
        if (resType === 'url') fR.readAsDataURL(fname); else fR.readAsText(fname);

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

});