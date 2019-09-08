function log(div, id, label, value) {
    if (typeof (value) != 'undefined') {
        $(div).append("<div class=\"alert alert - info\" style=\"word-wrap: break-word;\"><strong>" + label + "</strong><br/><p id=\"" + id + "\">" + value + "</p></div>");
    }
}

function HttpBearerTokenClient(token) {
    this.scheme = "Bearer";
    this.token = token;
}

HttpBearerTokenClient.prototype.get = function (url) {
    var scheme = this.scheme;
    var token = this.token;
    var settings = {
        type: "GET",
        url: url,
        dataType: "json",
        beforeSend: function (xhr) {
            xhr.setRequestHeader("Authorization", scheme + " " + token);
        }
    };
    return $.ajax(settings);
};

function GetToken(code, clientId, returnUrl) {
    $.ajax({
        url: '/Oauth2/GetToken',
        data: JSON.stringify({
            tokenRequest: {
                Code: code,
                ClientId: clientId,
                ReturnUrl: returnUrl
            }
        }),
        type: 'POST',
        contentType: 'application/json; charset=utf-8',
        success: function (data) {
            displayResult(data);
        },
        error: function () {
        }
    });
}

function ExchangeToken() {
    var code = $("#refreshtokenid").text();
    var clientId = $("#clientId").text();

    $.ajax({
        url: '/Oauth2/RenewToken',
        data: JSON.stringify({
            tokenRequest: {
                Code: code,
                ClientId: clientId
            }
        }),
        type: 'POST',
        contentType: 'application/json; charset=utf-8',
        success: function (data) {
            displayResult(data);
        },
        error: function () {
        }
    });
}

function displayResult(data) {
    $("#tokenRequestResult").html("");
    if (data.response.Error === null) {
        log("#tokenRequestResult", "accesstokenid", "Access token obtained: ", data.response.Access_Token);
        log("#tokenRequestResult", "idtokenid", "Id token obtained: ", data.response.Id_Token);
        log("#tokenRequestResult", "refreshtokenid", "Refresh token obtained: ", data.response.Refresh_Token);
    } else {
        log("#tokenRequestResult", "error", "Error: ", data.response.Error);
        log("#tokenRequestResult", "errorDescription", "Error description: ", data.response.Error_Description);
    }
}