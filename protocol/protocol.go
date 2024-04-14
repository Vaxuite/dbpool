package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

/* PG Error Severity Levels */
const (
	ErrorSeverityFatal   string = "FATAL"
	ErrorSeverityPanic   string = "PANIC"
	ErrorSeverityWarning string = "WARNING"
	ErrorSeverityNotice  string = "NOTICE"
	ErrorSeverityDebug   string = "DEBUG"
	ErrorSeverityInfo    string = "INFO"
	ErrorSeverityLog     string = "LOG"
)

/* PG Error Message Field Identifiers */
const (
	ErrorFieldSeverity         byte = 'S'
	ErrorFieldCode             byte = 'C'
	ErrorFieldMessage          byte = 'M'
	ErrorFieldMessageDetail    byte = 'D'
	ErrorFieldMessageHint      byte = 'H'
	ErrorFieldPosition         byte = 'P'
	ErrorFieldInternalPosition byte = 'p'
	ErrorFieldInternalQuery    byte = 'q'
	ErrorFieldWhere            byte = 'W'
	ErrorFieldSchemaName       byte = 's'
	ErrorFieldTableName        byte = 't'
	ErrorFieldColumnName       byte = 'c'
	ErrorFieldDataTypeName     byte = 'd'
	ErrorFieldConstraintName   byte = 'n'
	ErrorFieldFile             byte = 'F'
	ErrorFieldLine             byte = 'L'
	ErrorFieldRoutine          byte = 'R'
)

func CreatePasswordMessage(password string) []byte {
	message := NewMessageBuffer([]byte{})

	/* Set the message type */
	message.WriteByte(PasswordMessageType)

	/* Initialize the message length to zero. */
	message.WriteInt32(0)

	/* Add the password to the message. */
	message.WriteString(password)

	/* Update the message length */
	message.ResetLength(PGMessageLengthOffset)

	return message.Bytes()
}

type Error struct {
	Severity         string
	Code             string
	Message          string
	Detail           string
	Hint             string
	Position         string
	InternalPosition string
	InternalQuery    string
	Where            string
	SchemaName       string
	TableName        string
	ColumnName       string
	DataTypeName     string
	Constraint       string
	File             string
	Line             string
	Routine          string
}

func (e *Error) Error() string {
	return fmt.Sprintf("pg: %s: %s", e.Severity, e.Message)
}

func (e *Error) GetMessage() []byte {
	msg := NewMessageBuffer([]byte{})

	msg.WriteByte(ErrorMessageType)
	msg.WriteInt32(0)

	msg.WriteByte(ErrorFieldSeverity)
	msg.WriteString(e.Severity)

	msg.WriteByte(ErrorFieldCode)
	msg.WriteString(e.Code)

	msg.WriteByte(ErrorFieldMessage)
	msg.WriteString(e.Message)

	if e.Detail != "" {
		msg.WriteByte(ErrorFieldMessageDetail)
		msg.WriteString(e.Detail)
	}

	if e.Hint != "" {
		msg.WriteByte(ErrorFieldMessageHint)
		msg.WriteString(e.Hint)
	}

	msg.WriteByte(0x00) // null terminate the message

	msg.ResetLength(PGMessageLengthOffset)

	return msg.Bytes()
}

// ParseError parses a PG error message
func ParseError(e []byte) *Error {
	msg := NewMessageBuffer(e)
	msg.Seek(5)
	err := new(Error)

	for field, _ := msg.ReadByte(); field != 0; field, _ = msg.ReadByte() {
		value, _ := msg.ReadString()
		switch field {
		case ErrorFieldSeverity:
			err.Severity = value
		case ErrorFieldCode:
			err.Code = value
		case ErrorFieldMessage:
			err.Message = value
		case ErrorFieldMessageDetail:
			err.Detail = value
		case ErrorFieldMessageHint:
			err.Hint = value
		case ErrorFieldPosition:
			err.Position = value
		case ErrorFieldInternalPosition:
			err.InternalPosition = value
		case ErrorFieldInternalQuery:
			err.InternalQuery = value
		case ErrorFieldWhere:
			err.Where = value
		case ErrorFieldSchemaName:
			err.SchemaName = value
		case ErrorFieldTableName:
			err.TableName = value
		case ErrorFieldColumnName:
			err.ColumnName = value
		case ErrorFieldDataTypeName:
			err.DataTypeName = value
		case ErrorFieldConstraintName:
			err.Constraint = value
		case ErrorFieldFile:
			err.File = value
		case ErrorFieldLine:
			err.Line = value
		case ErrorFieldRoutine:
			err.Routine = value
		}
	}
	return err
}

/* PostgreSQL message length offset constants. */
const (
	PGMessageLengthOffsetStartup int = 0
	PGMessageLengthOffset        int = 1
)

const (
	// Class 00 — Successful Completion
	ErrorCodeSuccessfulCompletion = "00000" // successful_completion
	// Class 01 — Warning
	ErrorCodeWarning                                 = "01000" // warning
	ErrorCodeWarningDynamicResultSetsReturned        = "0100C" // dynamic_result_sets_returned
	ErrorCodeWarningImplicitZeroBitPadding           = "01008" // implicit_zero_bit_padding
	ErrorCodeWarningNullValueEliminatedInSetFunction = "01003" // null_value_eliminated_in_set_function
	ErrorCodeWarningPrivilegeNotGranted              = "01007" // privilege_not_granted
	ErrorCodeWarningPrivilegeNotRevoked              = "01006" // privilege_not_revoked
	ErrorCodeWarningStringDataRightTruncation        = "01004" // string_data_right_truncation
	ErrorCodeWarningDeprecatedFeature                = "01P01" // deprecated_feature
	// Class 02 — No Data (this is also a warning class per the SQL standard)
	ErrorCodeNoData                                = "02000" // no_data
	ErrorCodeNoAdditionalDynamicResultSetsReturned = "02001" // no_additional_dynamic_result_sets_returned
	// Class 03 — SQL Statement Not Yet Complete
	ErrorCodeSQLStatementNotYetComplete = "03000" // sql_statement_not_yet_complete
	// Class 08 — Connection Exception
	ErrorCodeConnectionException                            = "08000" // connection_exception
	ErrorCodeConnectionDoesNotExist                         = "08003" // connection_does_not_exist
	ErrorCodeConnectionFailure                              = "08006" // connection_failure
	ErrorCodeSQLClientUnableToEstablishSQLConnection        = "08001" // sqlclient_unable_to_establish_sqlconnection
	ErrorCodeSQLServerRejectedEstablishementOfSQLConnection = "08004" // sqlserver_rejected_establishment_of_sqlconnection
	ErrorCodeTransactionResolutionUnknown                   = "08007" // transaction_resolution_unknown
	ErrorCodeProtocolViolation                              = "08P01" // protocol_violation
	// Class 09 — Triggered Action Exception
	ErrorCodeTriggeredActionException = "09000" // triggered_action_exception
	// Class 0A — Feature Not Supported
	ErrorCodeFeatureNotSupported = "0A000" // feature_not_supported
	// Class 0B — Invalid Transaction Initiation
	ErrorCodeInvalidTransactionInitiation = "0B000" // invalid_transaction_initiation
	// Class 0F — Locator Exception
	ErrorCodeLocatorException            = "0F000" // locator_exception
	ErrorCodeInvalidLocatorSpecification = "0F001" // invalid_locator_specification
	// Class 0L — Invalid Grantor
	ErrorCodeInvalidGrantor        = "0L000" // invalid_grantor
	ErrorCodeInvalidGrantOperation = "0LP01" // invalid_grant_operation
	// Class 0P — Invalid Role Specification
	ErrorCodeInvalidRoleSpecification = "0P000" // invalid_role_specification
	// Class 0Z — Diagnostics Exception
	ErrorCodeDiagnosticsException                           = "0Z000" // diagnostics_exception
	ErrorCodeStackedDiagnosticsAccessedWithoutActiveHandler = "0Z002" // stacked_diagnostics_accessed_without_active_handler
	// Class 20 — Case Not Found
	ErrorCodeCaseNotFound = "20000" // case_not_found
	// Class 21 — Cardinality Violation
	ErrorCodeCardinalityViolation = "21000" // cardinality_violation
	// Class 22 — Data Exception
	ErrorCodeDataException                         = "22000" // data_exception
	ErrorCodeArraySubscriptError                   = "2202E" // array_subscript_error
	ErrorCodeCharacterNotInRepertoire              = "22021" // character_not_in_repertoire
	ErrorCodeDatatimeFieldOverflow                 = "22008" // datetime_field_overflow
	ErrorCodeDivisionByZero                        = "22012" // division_by_zero
	ErrorCodeErrorInAssignment                     = "22005" // error_in_assignment
	ErrorCodeEscapeCharacterConflict               = "2200B" // escape_character_conflict
	ErrorCodeIndicatorOverflow                     = "22022" // indicator_overflow
	ErrorCodeIntervalFieldOverflow                 = "22015" // interval_field_overflow
	ErrorCodeInvalidArgumentForLogarithm           = "2201E" // invalid_argument_for_logarithm
	ErrorCodeInvalidArgumentForNTileFunction       = "22014" // invalid_argument_for_ntile_function
	ErrorCodeInvalidArgumentForNthValueFunction    = "22016" // invalid_argument_for_nth_value_function
	ErrorCodeInvalidArgumentForPowerFunction       = "2201F" // invalid_argument_for_power_function
	ErrorCodeInvalidArgumentForWidthBucketFunction = "2201G" // invalid_argument_for_width_bucket_function
	ErrorCodeInvalidCharacterValueForCast          = "22018" // invalid_character_value_for_cast
	ErrorCodeInvalidDatatimeFormat                 = "22007" // invalid_datetime_format
	ErrorCodeInvalidEscapeCharacter                = "22019" // invalid_escape_character
	ErrorCodeInvalidEscapeOctet                    = "2200D" // invalid_escape_octet
	ErrorCodeInvalidEscapeSequence                 = "22025" // invalid_escape_sequence
	ErrorCodeNonStandardUseOfEscapeCharacter       = "22P06" // nonstandard_use_of_escape_character
	ErrorcodeInvalidIndicatorParameterValue        = "22010" // invalid_indicator_parameter_value
	ErrorCodeInvalidParameterValue                 = "22023" // invalid_parameter_value
	ErrorCodeInvalidRegularExpression              = "2201B" // invalid_regular_expression
	ErrorCodeInvalidRowCountInLimitClause          = "2201W" // invalid_row_count_in_limit_clause
	ErrorCodeInvalidRowCountInResultOffsetClause   = "2201X" // invalid_row_count_in_result_offset_clause
	ErrorCodeInvalidTablesampleArgument            = "2202H" // invalid_tablesample_argument
	ErrorCodeInvalidTablesampleRepeat              = "2202G" // invalid_tablesample_repeat
	ErrorCodeInvalidTimeZoneDisplacementValue      = "22009" // invalid_time_zone_displacement_value
	ErrorCodeInvalidInvalidUseOfEscapeCharacter    = "2200C" // invalid_use_of_escape_character
	ErrorCodeMostSpecificTypeMismatch              = "2200G" // most_specific_type_mismatch
	ErrorCodeNullValueNotAllowed                   = "22004" // null_value_not_allowed
	ErrorCodeNullValueNoIndicatorParameter         = "22002" // null_value_no_indicator_parameter
	ErrorCodeNumericValueOutOfRange                = "22003" // numeric_value_out_of_range
	ErrorCodeStringDataLengthMismatch              = "22026" // string_data_length_mismatch
	ErrorCodeStringDataRightTruncation             = "22001" // string_data_right_truncation
	ErrorCodeSubstringError                        = "22011" // substring_error
	ErrorCodeTrimError                             = "22027" // trim_error
	ErrorCodeUntermincatedCString                  = "22024" // unterminated_c_string
	ErrorCodeZeroLengthCharacterString             = "2200F" // zero_length_character_string
	ErrorCodeFloatingPointException                = "22P01" // floating_point_exception
	ErrorCodeInvalidTextRepresentation             = "22P02" // invalid_text_representation
	ErrorCodeInvalidBinaryRepresentation           = "22P03" // invalid_binary_representation
	ErrorCodeBadCopyFileFormat                     = "22P04" // bad_copy_file_format
	ErrorCodeUnstranslatableCharacter              = "22P05" // untranslatable_character
	ErrorCodeNotAnXMLDocument                      = "2200L" // not_an_xml_document
	ErrorCodeInvalideXMLDocument                   = "2200M" // invalid_xml_document
	ErrorCodeInvalidXMLContent                     = "2200N" // invalid_xml_content
	ErrorCodeInvalidXMLComment                     = "2200S" // invalid_xml_comment
	ErrorCodeInvalidXMLProcessingInstruction       = "2200T" // invalid_xml_processing_instruction
	// // Class 23 — Integrity Constraint Violation
	ErrorCodeIntegrityConstraintViolation = "23000" // integrity_constraint_violation
	ErrorCodeRestrictViolation            = "23001" // restrict_violation
	ErrorCodeNotNullViolation             = "23502" // not_null_violation
	ErrorCodeForeignKeyViolation          = "23503" // foreign_key_violation
	ErrorCodeUniqueViolation              = "23505" // unique_violation
	ErrorCodeCheckViolation               = "23514" // check_violation
	ErrorCodeExclusionViolation           = "23P01" // exclusion_violation
	// // Class 24 — Invalid Cursor State
	ErrorCodeInvalidCursorState = "24000" // invalid_cursor_state
	// // Class 25 — Invalid Transaction State
	ErrorCodeInvalidTransactionState                         = "25000" // invalid_transaction_state
	ErrorCodeActiveSQLTransaction                            = "25001" // active_sql_transaction
	ErrorCodeBranchTransactionAlreadyActive                  = "25002" // branch_transaction_already_active
	ErrorCodeHeldCursorRequiresSameIsolationLevel            = "25008" // held_cursor_requires_same_isolation_level
	ErrorCodeInappropriateAccessModeForBranchTransaction     = "25003" // inappropriate_access_mode_for_branch_transaction
	ErrorCodeInappropriateIsolationLevelForBranchTransaction = "25004" // inappropriate_isolation_level_for_branch_transaction
	ErrorCodeNoActiveSQLTransactionForBranchTransaction      = "25005" // no_active_sql_transaction_for_branch_transaction
	ErrorCodeReadOnlySQLTransaction                          = "25006" // read_only_sql_transaction
	ErrorCodeSchemaAndDataStatementMixingNotSupported        = "25007" // schema_and_data_statement_mixing_not_supported
	ErrorCodeNoActiveSQLTransaction                          = "25P01" // no_active_sql_transaction
	ErrorCodeInFailedSQLTransaction                          = "25P02" // in_failed_sql_transaction
	ErrorCodeIdleInTransactionSessionTimeout                 = "25P03" // idle_in_transaction_session_timeout
	// Class 26 — Invalid SQL Statement Name
	ErrorCodeInvalidSQLStatementName = "26000" // invalid_sql_statement_name
	// Class 27 — Triggered Data Change Violation
	ErrorCodeTriggeredDataChangeViolation = "27000" // triggered_data_change_violation
	// Class 28 — Invalid Authorization Specification
	ErrorCodeInvalidAuthorizationSpecification = "28000" // invalid_authorization_specification
	ErrorCodeInvalidPassword                   = "28P01" // invalid_password
	// Class 2B — Dependent Privilege Descriptors Still Exist
	ErrorCodeDependentPrivilegeDescriptorsStillExist = "2B000" // dependent_privilege_descriptors_still_exist
	ErrorCodeDependentObjectsStillExist              = "2BP01" // dependent_objects_still_exist
	// Class 2D — Invalid Transaction Termination
	ErrorCodeInvalidTransactionTermination = "2D000" // invalid_transaction_termination
	// Class 2F — SQL Routine Exception
	ErrorCodeRoutineSQLRuntimeException               = "2F000" // sql_routine_exception
	ErrorCodeRoutineFunctionExecutedNoReturnStatement = "2F005" // function_executed_no_return_statement
	ErrorCodeRoutineModifyingSQLDataNotPermitted      = "2F002" // modifying_sql_data_not_permitted
	ErrorCodeRoutineProhibitedSQLStatementAttempted   = "2F003" // prohibited_sql_statement_attempted
	ErrorCodeRoutineReadingSQLDataNotPermitted        = "2F004" // reading_sql_data_not_permitted
	// Class 34 — Invalid Cursor Name
	ErrorCodeInvalidCursorName = "34000" // invalid_cursor_name
	// Class 38 — External Routine Exception
	ErrorCodeExternalRoutineException                       = "38000" // external_routine_exception
	ErrorCodeExternalRoutineContainingSQLNotPermitted       = "38001" // containing_sql_not_permitted
	ErrorCodeExternalRoutineModifyingSQLDataNotPermitted    = "38002" // modifying_sql_data_not_permitted
	ErrorCodeExternalRoutineProhibitedSQLStatementAttempted = "38003" // prohibited_sql_statement_attempted
	ErrorCodeExternalRoutineReadingSQLDataNotPermitted      = "38004" // reading_sql_data_not_permitted
	// Class 39 — External Routine Invocation Exception
	ErrorCodeExternalRoutineInvocationException     = "39000" // external_routine_invocation_exception
	ErrorCodeExternalRoutineInvalidSQLStateReturned = "39001" // invalid_sqlstate_returned
	ErrorCodeExternalRoutineNullValueNotAllowed     = "39004" // null_value_not_allowed
	ErrorCodeExternalRoutineTriggerProtocolViolated = "39P01" // trigger_protocol_violated
	ErrorCodeExternalRoutineSRFProtocolViolated     = "39P02" // srf_protocol_violated
	ErrorCodeExternalRoutineEventTriggerProtocol    = "39P03" // event_trigger_protocol_violated
	// Class 3B — Savepoint Exception
	ErrorCodeSavepointException            = "3B000" // savepoint_exception
	ErrorCodeInvalidSavepointSpecification = "3B001" // invalid_savepoint_specification
	// Class 3D — Invalid Catalog Name
	ErrorCodeInvalidCatalogName = "3D000" // invalid_catalog_name
	// Class 3F — Invalid Schema Name
	ErrorCodeInvalidSchemaName = "3F000" // invalid_schema_name
	// Class 40 — Transaction Rollback
	ErrorCodeTransactionRollback                     = "40000" // transaction_rollback
	ErrorCodeTransactionIntegrityConstraintViolation = "40002" // transaction_integrity_constraint_violation
	ErrorCodeSerializationFailure                    = "40001" // serialization_failure
	ErrorCodeStatementCompletionUnknown              = "40003" // statement_completion_unknown
	ErrorCodeDeadlockDetected                        = "40P01" // deadlock_detected
	// Class 42 — Syntax Error or Access Rule Violation
	ErrorCodeSyntaxErrorOrAccessRuleViolation = "42000" // syntax_error_or_access_rule_violation
	ErrorCodeSyntaxError                      = "42601" // syntax_error
	ErrorCodeInsufficientPrivilege            = "42501" // insufficient_privilege
	ErrorCodeCannotCoerce                     = "42846" // cannot_coerce
	ErrorCodeGroupingError                    = "42803" // grouping_error
	ErrorCodeWindowingError                   = "42P20" // windowing_error
	ErrorCodeInvalidRecursion                 = "42P19" // invalid_recursion
	ErrorCodeInvalidForeignKey                = "42830" // invalid_foreign_key
	ErrorCodeInvalidName                      = "42602" // invalid_name
	ErrorCodeNameTooLong                      = "42622" // name_too_long
	ErrorCodeReservedName                     = "42939" // reserved_name
	ErrorCodeDatatypeMismatch                 = "42804" // datatype_mismatch
	ErrorCodeIndeterminateDatatype            = "42P18" // indeterminate_datatype
	ErrorCodeCollationMismatch                = "42P21" // collation_mismatch
	ErrorCodeIndeterminateCollation           = "42P22" // indeterminate_collation
	ErrorCodeWrongObjectType                  = "42809" // wrong_object_type
	ErrorCodeUndefinedColumn                  = "42703" // undefined_column
	ErrorCodeUndefinedFunction                = "42883" // undefined_function
	ErrorCodeUndefinedTable                   = "42P01" // undefined_table
	ErrorCodeUndefinedParameter               = "42P02" // undefined_parameter
	ErrorCodeUndefinedObject                  = "42704" // undefined_object
	ErrorCodeDuplicateColumn                  = "42701" // duplicate_column
	ErrorCodeDuplicateCursor                  = "42P03" // duplicate_cursor
	ErrorCodeDuplicateDatabase                = "42P04" // duplicate_database
	ErrorCodeDuplicateFunction                = "42723" // duplicate_function
	ErrorCodeDuplicatePreparedStatement       = "42P05" // duplicate_prepared_statement
	ErrorCodeDuplicateSchema                  = "42P06" // duplicate_schema
	ErrorCodeDuplicateTable                   = "42P07" // duplicate_table
	ErrorCodeDuplicateAlias                   = "42712" // duplicate_alias
	ErrorCodeDuplicateObject                  = "42710" // duplicate_object
	ErrorCodeAmbiguousColumn                  = "42702" // ambiguous_column
	ErrorCodeAmbiguousFunction                = "42725" // ambiguous_function
	ErrorCodeAmbiguousParameter               = "42P08" // ambiguous_parameter
	ErrorCodeAmbiguousAlias                   = "42P09" // ambiguous_alias
	ErrorCodeInvalidColumnReference           = "42P10" // invalid_column_reference
	ErrorCodeInvalidColumnDefinition          = "42611" // invalid_column_definition
	ErrorCodeInvalidCursorDefinition          = "42P11" // invalid_cursor_definition
	ErrorCodeInvalidDatabaseDefinition        = "42P12" // invalid_database_definition
	ErrorCodeInvalidFunctionDefinition        = "42P13" // invalid_function_definition
	ErrorCodeInvalidStatementDefinition       = "42P14" // invalid_prepared_statement_definition
	ErrorCodeInvalidSchemaDefinition          = "42P15" // invalid_schema_definition
	ErrorCodeInvalidTableDefinition           = "42P16" // invalid_table_definition
	ErrorCodeInvalidObjectDefinition          = "42P17" // invalid_object_definition
	// Class 44 — WITH CHECK OPTION Violation
	ErrorCodeWithCheckOptionViolation = "44000" // with_check_option_violation
	// Class 53 — Insufficient Resources
	ErrorCodeInsufficientResources      = "53000" // insufficient_resources
	ErrorCodeDiskFull                   = "53100" // disk_full
	ErrorCodeOutOfMemory                = "53200" // out_of_memory
	ErrorCodeTooManyConnections         = "53300" // too_many_connections
	ErrorCodeConfigurationLimitExceeded = "53400" // configuration_limit_exceeded
	// Class 54 — Program Limit Exceeded
	ErrorCodeProgramLimitExceeded = "54000" // program_limit_exceeded
	ErrorCodeStatementTooComplex  = "54001" // statement_too_complex
	ErrorCodeTooManyColumns       = "54011" // too_many_columns
	ErrorCodeTooManyArguments     = "54023" // too_many_arguments
	// Class 55 — Object Not In Prerequisite State
	ErrorCodeObjectNotInPrerequisiteState = "55000" // object_not_in_prerequisite_state
	ErrorCodeObjectInUse                  = "55006" // object_in_use
	ErrorCodeCantChangeRuntimeParam       = "55P02" // cant_change_runtime_param
	ErrorCodeLockNotAvailable             = "55P03" // lock_not_available
	// Class 57 — Operator Intervention
	ErrorCodeOperatorIntervention = "57000" // operator_intervention
	ErrorCodeQueryCanceled        = "57014" // query_canceled
	ErrorCodeAdminShutdown        = "57P01" // admin_shutdown
	ErrorCodeCrashShutdown        = "57P02" // crash_shutdown
	ErrorCodeCannotConnectNow     = "57P03" // cannot_connect_now
	ErrorCodeDatabaseDropped      = "57P04" // database_dropped
	// Class 58 — System Error (errors external to PostgreSQL itself)
	ErrorCodeSystemError   = "58000" // system_error
	ErrorCodeIOError       = "58030" // io_error
	ErrorCodeUndefinedFile = "58P01" // undefined_file
	ErrorCodeDuplicateFile = "58P02" // duplicate_file
	// Class 72 — Snapshot Failure
	ErrorCodeSnapshotTooOld = "72000" // snapshot_too_old
	// Class F0 — Configuration File Error
	ErrorCodeConfigFileError = "F0000" // config_file_error
	ErrorCodeLockFileExists  = "F0001" // lock_file_exists
	// Class HV — Foreign Data Wrapper Error (SQL/MED)
	ErrorCodeFDWError                             = "HV000" // fdw_error
	ErrorCodeFDWColumnNameNotFound                = "HV005" // fdw_column_name_not_found
	ErrorCodeFDWDynamicParameterValueNeeded       = "HV002" // fdw_dynamic_parameter_value_needed
	ErrorCodeFDWFunctionSequenceError             = "HV010" // fdw_function_sequence_error
	ErrorCodeFDWInconsistentDescriptorInformation = "HV021" // fdw_inconsistent_descriptor_information
	ErrorCodeFDWInvalidAttributeValue             = "HV024" // fdw_invalid_attribute_value
	ErrorCodeFDWInvalidColumnName                 = "HV007" // fdw_invalid_column_name
	ErrorCodeFDWInvalidColumnNumber               = "HV008" // fdw_invalid_column_number
	ErrorCodeFDWInvalidDataType                   = "HV004" // fdw_invalid_data_type
	ErrorCodeFDWInvalidDataTypeDescriptors        = "HV006" // fdw_invalid_data_type_descriptors
	ErrorCodeFDWInvalidDescriptorFieldIdentifier  = "HV091" // fdw_invalid_descriptor_field_identifier
	ErrorCodeFDWInvalidHandle                     = "HV00B" // fdw_invalid_handle
	ErrorCodeFDWInvalidOptionIndex                = "HV00C" // fdw_invalid_option_index
	ErrorCodeFDWInvalidOptionName                 = "HV00D" // fdw_invalid_option_name
	ErrorCodeFDWInvalidStringLengthOrBufferLength = "HV090" // fdw_invalid_string_length_or_buffer_length
	ErrorCodeFDWInvalidStringFormat               = "HV00A" // fdw_invalid_string_format
	ErrorCodeFDWInvalidUseOfNullPointer           = "HV009" // fdw_invalid_use_of_null_pointer
	ErrorCodeFDWTooManyHandles                    = "HV014" // fdw_too_many_handles
	ErrorCodeFDWOutOfMemory                       = "HV001" // fdw_out_of_memory
	ErrorCodeFDWNoSchemas                         = "HV00P" // fdw_no_schemas
	ErrorCodeFDWOptionNameNotFound                = "HV00J" // fdw_option_name_not_found
	ErrorCodeFDWReplyHandle                       = "HV00K" // fdw_reply_handle
	ErrorCodeFDWSchemaNotFound                    = "HV00Q" // fdw_schema_not_found
	ErrorCodeFDWTableNotFound                     = "HV00R" // fdw_table_not_found
	ErrorCodeFDWUnableToCreateExecution           = "HV00L" // fdw_unable_to_create_execution
	ErrorCodeFDWUnableToCreateReply               = "HV00M" // fdw_unable_to_create_reply
	ErrorCodeFDWUnableToEstablishConnection       = "HV00N" // fdw_unable_to_establish_connection
	// Class P0 — PL/pgSQL Error
	ErrorCodePLPGSQLError   = "P0000" // plpgsql_error
	ErrorCodeRaiseException = "P0001" // raise_exception
	ErrorCodeNoDataFound    = "P0002" // no_data_found
	ErrorCodeTooManyRows    = "P0003" // too_many_rows
	ErrorCodeAssertFailure  = "P0004" // assert_failure
	// Class XX — Internal Error
	ErrorCodeInternalError  = "XX000" // internal_error
	ErrorCodeDataCorrupted  = "XX001" // data_corrupted
	ErrorCodeIndexCorrupted = "XX002" // index_corrupted
)

// MessageBuffer is a variable-sized byte buffer used to read and write
// PostgreSQL Frontend and Backend messages.
//
// A separate instance of a MessageBuffer should be use for reading and writing.
type MessageBuffer struct {
	buffer *bytes.Buffer
}

// NewMessageBuffer creates and intializes a new MessageBuffer using message as its
// initial contents.
func NewMessageBuffer(message []byte) *MessageBuffer {
	return &MessageBuffer{
		buffer: bytes.NewBuffer(message),
	}
}

// ReadInt32 reads an int32 from the message buffer.
//
// This function will read the next 4 available bytes from the message buffer
// and return them as an int32. If an error occurs then 0 and the error are
// returned.
func (message *MessageBuffer) ReadInt32() (int32, error) {
	value := make([]byte, 4)

	if _, err := message.buffer.Read(value); err != nil {
		return 0, err
	}

	return int32(binary.BigEndian.Uint32(value)), nil
}

// ReadInt16 reads an int16 from the message buffer.
//
// This function will read the next 2 available bytes from the message buffer
// and return them as an int16. If an error occurs then 0 and the error are
// returned.
func (message *MessageBuffer) ReadInt16() (int16, error) {
	value := make([]byte, 2)

	if _, err := message.buffer.Read(value); err != nil {
		return 0, err
	}

	return int16(binary.BigEndian.Uint16(value)), nil
}

// ReadByte reads a byte from the message buffer.
//
// This function will read and return the next available byte from the message
// buffer.
func (message *MessageBuffer) ReadByte() (byte, error) {
	return message.buffer.ReadByte()
}

// ReadBytes reads a variable size byte array defined by count from the message
// buffer.
//
// This function will read and return the number of bytes as specified by count.
func (message *MessageBuffer) ReadBytes(count int) ([]byte, error) {
	value := make([]byte, count)

	if _, err := message.buffer.Read(value); err != nil {
		return nil, err
	}

	return value, nil
}

// ReadString reads a string from the message buffer.
//
// This function will read and return the next Null terminated string from the
// message buffer.
func (message *MessageBuffer) ReadString() (string, error) {
	str, err := message.buffer.ReadString(0x00)
	return strings.Trim(str, "\x00"), err
}

// WriteByte will write the specified byte to the message buffer.
func (message *MessageBuffer) WriteByte(value byte) error {
	return message.buffer.WriteByte(value)
}

// WriteBytes writes a variable size byte array specified by 'value' to the
// message buffer.
//
// This function will return the number of bytes written, if the buffer is not
// large enough to hold the value then an error is returned.
func (message *MessageBuffer) WriteBytes(value []byte) (int, error) {
	return message.buffer.Write(value)
}

// WriteInt16 will write a 2 byte int16 to the message buffer.
func (message *MessageBuffer) WriteInt16(value int16) (int, error) {
	x := make([]byte, 2)
	binary.BigEndian.PutUint16(x, uint16(value))
	return message.WriteBytes(x)
}

// WriteInt32 will write a 4 byte int32 to the message buffer.
func (message *MessageBuffer) WriteInt32(value int32) (int, error) {
	x := make([]byte, 4)
	binary.BigEndian.PutUint32(x, uint32(value))
	return message.WriteBytes(x)
}

// WriteString will write a NULL terminated string to the buffer.  It is
// assumed that the incoming string has *NOT* been NULL terminated.
func (message *MessageBuffer) WriteString(value string) (int, error) {
	return message.buffer.WriteString((value + "\000"))
}

// ResetLength will reset the message length for the message.
//
// offset should be one of the PGMessageLengthOffset* constants.
func (message *MessageBuffer) ResetLength(offset int) {
	/* Get the contents of the buffer. */
	b := message.buffer.Bytes()

	/* Get the start of the message length bytes. */
	s := b[offset:]

	/* Determine the new length and set it. */
	binary.BigEndian.PutUint32(s, uint32(len(s)))
}

// Bytes gets the contents of the message buffer. This function is only
// useful after 'Write' operations as the underlying implementation will return
// the 'unread' portion of the buffer.
func (message *MessageBuffer) Bytes() []byte {
	return message.buffer.Bytes()
}

// Reset resets the buffer to empty.
func (message *MessageBuffer) Reset() {
	message.buffer.Reset()
}

// Seek moves the current position of the buffer.
func (message *MessageBuffer) Seek(pos int) {
	message.buffer.Next(pos)
}

func CreateStartupMessage(username string, database string, options map[string]string) []byte {
	message := NewMessageBuffer([]byte{})

	/* Temporarily set the message length to 0. */
	message.WriteInt32(0)

	/* Set the protocol version. */
	message.WriteInt32(ProtocolVersion)

	/*
	 * The protocol version number is followed by one or more pairs of
	 * parameter name and value strings. A zero byte is required as a
	 * terminator after the last name/value pair. Parameters can appear in any
	 * order. 'user' is required, others are optional.
	 */

	/* Set the 'user' parameter.  This is the only *required* parameter. */
	message.WriteString("user")
	message.WriteString(username)

	/*
	 * Set the 'database' parameter.  If no database name has been specified,
	 * then the default value is the user's name.
	 */
	message.WriteString("database")
	message.WriteString(database)

	/* Set the remaining options as specified. */
	for option, value := range options {
		message.WriteString(option)
		message.WriteString(value)
	}

	/* The message should end with a NULL byte. */
	message.WriteByte(0x00)

	/* update the msg len */
	message.ResetLength(PGMessageLengthOffsetStartup)

	return message.Bytes()
}

/* PostgreSQL Protocol Version/Code constants */
const (
	ProtocolVersion int32 = 196608
	SSLRequestCode  int32 = 80877103

	/* SSL Responses */
	SSLAllowed    byte = 'S'
	SSLNotAllowed byte = 'N'
)

/* PostgreSQL Message Type constants. */
const (
	AuthenticationMessageType  byte = 'R'
	ErrorMessageType           byte = 'E'
	EmptyQueryMessageType      byte = 'I'
	DescribeMessageType        byte = 'D'
	RowDescriptionMessageType  byte = 'T'
	DataRowMessageType         byte = 'D'
	QueryMessageType           byte = 'Q'
	CommandCompleteMessageType byte = 'C'
	TerminateMessageType       byte = 'X'
	NoticeMessageType          byte = 'N'
	PasswordMessageType        byte = 'p'
	ReadyForQueryMessageType   byte = 'Z'
)

/* PostgreSQL Authentication Method constants. */
const (
	AuthenticationOk          int32 = 0
	AuthenticationKerberosV5  int32 = 2
	AuthenticationClearText   int32 = 3
	AuthenticationMD5         int32 = 5
	AuthenticationSCM         int32 = 6
	AuthenticationGSS         int32 = 7
	AuthenticationGSSContinue int32 = 8
	AuthenticationSSPI        int32 = 9
)

func GetVersion(message []byte) int32 {
	var code int32

	reader := bytes.NewReader(message[4:8])
	binary.Read(reader, binary.BigEndian, &code)

	return code
}

/*
 * Get the message type the provided message.
 *
 * message - the message
 */
func GetMessageType(message []byte) byte {
	return message[0]
}

/*
 * Get the message length of the provided message.
 *
 * message - the message
 */
func GetMessageLength(message []byte) int32 {
	var messageLength int32

	reader := bytes.NewReader(message[1:5])
	binary.Read(reader, binary.BigEndian, &messageLength)

	return messageLength
}

/* IsAuthenticationOk
 *
 * Check an Authentication Message to determine if it is an AuthenticationOK
 * message.
 */
func IsAuthenticationOk(message []byte) bool {
	/*
	 * If the message type is not an Authentication message, then short circuit
	 * and return false.
	 */
	if GetMessageType(message) != AuthenticationMessageType {
		return false
	}

	var messageValue int32

	// Get the message length.
	messageLength := GetMessageLength(message)

	// Get the message value.
	reader := bytes.NewReader(message[5:9])
	binary.Read(reader, binary.BigEndian, &messageValue)

	return (messageLength == 8 && messageValue == AuthenticationOk)
}

func GetTerminateMessage() []byte {
	var buffer []byte
	buffer = append(buffer, 'X')

	//make msg len 1 for now
	x := make([]byte, 4)
	binary.BigEndian.PutUint32(x, uint32(4))
	buffer = append(buffer, x...)
	return buffer
}
