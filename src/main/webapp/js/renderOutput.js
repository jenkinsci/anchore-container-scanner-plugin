const actionLookup = {
  stop: 0,
  warn: 1,
  go: 2,
};

const severityLookup = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  negligible: 4,
  unknown: 5
}

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

function severity(source, type, val) {
  var el = '<span>' + source + '</span>';
  if ((typeof source === 'string') && source.trim().toLowerCase().match(/(critical|high|medium|low|negligible|unknown)/g)) {
    switch (source.trim().toLowerCase()) {
      case 'critical': {
        el = '<span style="display:none;">' + severityLookup[source.toLowerCase()]
            + '</span><span class="label label-danger">' + source + '</span>';
        break;
      }
      case 'high': {
        el = '<span style="display:none;">' + severityLookup[source.toLowerCase()]
            + '</span><span class="label label-warning">' + source + '</span>';
        break;
      }
      case 'medium': {
        el = '<span style = "display:none;">' + severityLookup[source.toLowerCase()]
            + '</span><span class="label label-info">' + source + '</span>';
        break;
      }
      case 'low': {
        el = '<span style="display:none;">' + severityLookup[source.toLowerCase()]
            + '</span><span class="label label-success">' + source + '</span>';
        break;
      }
      case 'negligible': {
        el = '<span style="display:none;">' + severityLookup[source.toLowerCase()]
            + '</span><span class="label label-default">' + source + '</span>';
        break;
      }
      case 'unknown': {
        el = '<span style = "display:none;">' + severityLookup[source.toLowerCase()]
            + '</span><span class="label label-default">' + source + '</span>';
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
  });
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

function buildSecurityTable(tableId, outputFile) {
  jQuery.getJSON(outputFile, function (tableObj) {
    jQuery(document).ready(function () {
      jQuery(tableId).DataTable({
        retrieve: true,
        data: tableObj.data,
        columns: tableObj.columns,
        order: [[2, 'asc'], [0, 'asc']],
        columnDefs: [
          {
            targets: 2,
            render: severity
          }
        ]
      });
    });
  });
}
