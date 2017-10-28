const actionLookup = {
  stop: 0,
  warn: 1,
  go: 2,
};

function gateAction(source, type, val) {
  var el = '<span>' + source + '</span>';
  if ((typeof source === 'string') && source.trim().toLowerCase().match(/(stop|go|warn)/g)) {
    switch (source.trim().toLowerCase()) {
      case 'stop': {
        el = '<span style="display:none;">' + actionLookup[source.toLowerCase()]
            + '</span><span class="label label-danger">' + source.toUpperCase() + '</span>';
        break;
      }
      case 'go': {
        el = '<span style="display:none;">' + actionLookup[source.toLowerCase()]
            + '</span><span class="label label-success">' + source.toUpperCase() + '</span>';
        break;
      }
      case 'warn': {
        el = '<span style = "display:none;">' + actionLookup[source.toLowerCase()]
            + '</span><span class="label label-warning">' + source.toUpperCase() + '</span>';
        break;
      }
    }
  }
  return el;
}

function buildPolicyEvalTable(tableId, outputFile) {
  jQuery.getJSON(outputFile, function (data) {
        var headers = [];
        var rows = [];
        jQuery.each(data, function (imageId, imageIdObj) {
          if (headers.length === 0) {
            jQuery.each(imageIdObj.result.header, function (i, header) {
              var headerObj = new Object();
              headerObj.title = header.replace('_', ' ');
              headers.push(headerObj);
            });
          }
          jQuery.merge(rows, imageIdObj.result.rows);
        });

        jQuery(document).ready(function () {
          jQuery(tableId).DataTable({
            retrieve: true,
            data: rows,
            columns: headers,
            order: [[6, 'asc']],
            columnDefs: [
              {
                targets: 6,
                render: gateAction
              }
            ]
          });
        });
      }
  );
}

function buildTableFromAnchoreOutput(tableId, outputFile) {
  jQuery.getJSON(outputFile, function (data) {
    var headers = [];
    var rows = [];
    jQuery.each(data, function (imageId, imageIdObj) {
      if (headers.length === 0) {
        jQuery.each(imageIdObj.result.header, function (i, header) {
          var headerObj = new Object();
          headerObj.title = header.replace('_', ' ');
          headers.push(headerObj);
        });
      }
      jQuery.merge(rows, imageIdObj.result.rows);
    });

    jQuery(document).ready(function () {
      jQuery(tableId).DataTable({
        retrieve: true,
        data: rows,
        columns: headers
      });
    });
  });
}

function buildTableFromAnchoreOutputWithUrls(tableId, outputFile, index) {
  var urlRegex = /(https?:\/\/[^\s\)]+)/g;

  jQuery.getJSON(outputFile, function (data) {
    var headers = [];
    var rows = [];

    jQuery.each(data, function (counter, imageIdObj) {
      if (headers.length === 0) {
        jQuery.each(imageIdObj.result.header, function (i, header) {
          var headerObj = new Object();
          headerObj.title = header.replace('_', ' ');
          headers.push(headerObj);
        });
      }

      jQuery.merge(rows, imageIdObj.result.rows);
    });

    jQuery(document).ready(function () {
      jQuery(tableId).DataTable({
        retrieve: true,
        data: rows,
        columns: headers,
        columnDefs: [
          {
            render: function (data, type, row) {
              return data.replace(urlRegex, '<a href="$1">$1</a>');
            },
            targets: index
          }
        ]
      });
    });
  });
}

function buildPolicyEvalSummaryTable(tableId, tableObj) {
  jQuery(document).ready(function () {
    jQuery(tableId).DataTable({
      retrieve: true,
      data: tableObj.rows,
      columns: tableObj.header,
      order: [[4, 'asc']],
      columnDefs: [
        {
          targets: 1,
          render: function (source, type, val) {
            return '<span class="label label-danger">' + source + '</span>';
          }
        },
        {
          targets: 2,
          render: function (source, type, val) {
            return '<span class="label label-warning">' + source + '</span>';
          }
        },
        {
          targets: 3,
          render: function (source, type, val) {
            return '<span class="label label-success">' + source + '</span>';
          }
        },
        {
          targets: 4,
          render: gateAction
        }
      ]
    });
  });
}
