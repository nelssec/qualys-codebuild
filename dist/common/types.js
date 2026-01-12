"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.QScannerExitCode = exports.VALID_PODS = void 0;
exports.VALID_PODS = [
    'US1', 'US2', 'US3', 'US4',
    'EU1', 'EU2',
    'CA1', 'IN1', 'AU1', 'UK1', 'AE1', 'KSA1',
];
var QScannerExitCode;
(function (QScannerExitCode) {
    QScannerExitCode[QScannerExitCode["SUCCESS"] = 0] = "SUCCESS";
    QScannerExitCode[QScannerExitCode["GENERIC_ERROR"] = 1] = "GENERIC_ERROR";
    QScannerExitCode[QScannerExitCode["INVALID_PARAMETER"] = 2] = "INVALID_PARAMETER";
    QScannerExitCode[QScannerExitCode["LOGGER_INIT_FAILED"] = 3] = "LOGGER_INIT_FAILED";
    QScannerExitCode[QScannerExitCode["FILESYSTEM_ARTIFACT_FAILED"] = 5] = "FILESYSTEM_ARTIFACT_FAILED";
    QScannerExitCode[QScannerExitCode["IMAGE_ARTIFACT_FAILED"] = 6] = "IMAGE_ARTIFACT_FAILED";
    QScannerExitCode[QScannerExitCode["IMAGE_ARCHIVE_ARTIFACT_FAILED"] = 7] = "IMAGE_ARCHIVE_ARTIFACT_FAILED";
    QScannerExitCode[QScannerExitCode["IMAGE_STORAGE_DRIVER_ARTIFACT_FAILED"] = 8] = "IMAGE_STORAGE_DRIVER_ARTIFACT_FAILED";
    QScannerExitCode[QScannerExitCode["CONTAINER_ARTIFACT_FAILED"] = 9] = "CONTAINER_ARTIFACT_FAILED";
    QScannerExitCode[QScannerExitCode["OTHER_ARTIFACT_FAILED"] = 10] = "OTHER_ARTIFACT_FAILED";
    QScannerExitCode[QScannerExitCode["METADATA_SCAN_FAILED"] = 11] = "METADATA_SCAN_FAILED";
    QScannerExitCode[QScannerExitCode["OS_SCAN_FAILED"] = 12] = "OS_SCAN_FAILED";
    QScannerExitCode[QScannerExitCode["SCA_SCAN_FAILED"] = 13] = "SCA_SCAN_FAILED";
    QScannerExitCode[QScannerExitCode["SECRET_SCAN_FAILED"] = 14] = "SECRET_SCAN_FAILED";
    QScannerExitCode[QScannerExitCode["OS_NOT_FOUND"] = 15] = "OS_NOT_FOUND";
    QScannerExitCode[QScannerExitCode["MALWARE_SCAN_FAILED"] = 16] = "MALWARE_SCAN_FAILED";
    QScannerExitCode[QScannerExitCode["OS_NOT_SUPPORTED"] = 17] = "OS_NOT_SUPPORTED";
    QScannerExitCode[QScannerExitCode["FILE_INSIGHT_SCAN_FAILED"] = 18] = "FILE_INSIGHT_SCAN_FAILED";
    QScannerExitCode[QScannerExitCode["COMPLIANCE_SCAN_FAILED"] = 19] = "COMPLIANCE_SCAN_FAILED";
    QScannerExitCode[QScannerExitCode["MANIFEST_SCAN_FAILED"] = 20] = "MANIFEST_SCAN_FAILED";
    QScannerExitCode[QScannerExitCode["WINREGISTRY_SCAN_FAILED"] = 21] = "WINREGISTRY_SCAN_FAILED";
    QScannerExitCode[QScannerExitCode["JSON_RESULT_HANDLER_FAILED"] = 30] = "JSON_RESULT_HANDLER_FAILED";
    QScannerExitCode[QScannerExitCode["CHANGELIST_CREATION_FAILED"] = 31] = "CHANGELIST_CREATION_FAILED";
    QScannerExitCode[QScannerExitCode["CHANGELIST_COMPRESSION_FAILED"] = 32] = "CHANGELIST_COMPRESSION_FAILED";
    QScannerExitCode[QScannerExitCode["CHANGELIST_UPLOAD_FAILED"] = 33] = "CHANGELIST_UPLOAD_FAILED";
    QScannerExitCode[QScannerExitCode["SPDX_HANDLER_FAILED"] = 34] = "SPDX_HANDLER_FAILED";
    QScannerExitCode[QScannerExitCode["CDX_HANDLER_FAILED"] = 35] = "CDX_HANDLER_FAILED";
    QScannerExitCode[QScannerExitCode["SBOM_COMPRESSION_FAILED"] = 36] = "SBOM_COMPRESSION_FAILED";
    QScannerExitCode[QScannerExitCode["SBOM_UPLOAD_FAILED"] = 37] = "SBOM_UPLOAD_FAILED";
    QScannerExitCode[QScannerExitCode["SECRET_RESULT_CREATION_FAILED"] = 38] = "SECRET_RESULT_CREATION_FAILED";
    QScannerExitCode[QScannerExitCode["SECRET_RESULT_UPLOAD_FAILED"] = 39] = "SECRET_RESULT_UPLOAD_FAILED";
    QScannerExitCode[QScannerExitCode["FAILED_TO_GET_VULN_REPORT"] = 40] = "FAILED_TO_GET_VULN_REPORT";
    QScannerExitCode[QScannerExitCode["FAILED_TO_GET_POLICY_EVALUATION_RESULT"] = 41] = "FAILED_TO_GET_POLICY_EVALUATION_RESULT";
    QScannerExitCode[QScannerExitCode["POLICY_EVALUATION_DENY"] = 42] = "POLICY_EVALUATION_DENY";
    QScannerExitCode[QScannerExitCode["POLICY_EVALUATION_AUDIT"] = 43] = "POLICY_EVALUATION_AUDIT";
})(QScannerExitCode || (exports.QScannerExitCode = QScannerExitCode = {}));
//# sourceMappingURL=types.js.map