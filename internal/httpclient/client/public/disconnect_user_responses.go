// Code generated by go-swagger; DO NOT EDIT.

package public

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// DisconnectUserReader is a Reader for the DisconnectUser structure.
type DisconnectUserReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DisconnectUserReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 302:
		result := NewDisconnectUserFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewDisconnectUserFound creates a DisconnectUserFound with default headers values
func NewDisconnectUserFound() *DisconnectUserFound {
	return &DisconnectUserFound{}
}

/*DisconnectUserFound handles this case with default header values.

Empty responses are sent when, for example, resources are deleted. The HTTP status code for empty responses is
typically 201.
*/
type DisconnectUserFound struct {
}

func (o *DisconnectUserFound) Error() string {
	return fmt.Sprintf("[GET /oauth2/sessions/logout][%d] disconnectUserFound ", 302)
}

func (o *DisconnectUserFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
