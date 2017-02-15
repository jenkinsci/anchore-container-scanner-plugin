function buildDataTable(jsonUri, tableId) {
  jQuery.getJSON(jsonUri, function (data) {
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
        data: rows,
        columns: headers
      });
    });
  });
}