import { ResponsePayload } from '../../interfaces/objects/ResponsePayload';

export class CommonResponses {
  public success(data: ResponsePayload) {
    const { res } = data;

    return res.status(200).json({
      status: 1,
      message: 'success'
    })
  }

  public badRequest(data: ResponsePayload) {
    const { res } = data;

    return res.status(400).json({
      status: -1,
      message: 'bad-request'
    })
  }

  public unauthorized(data: ResponsePayload) {
    const { res } = data;

    return res.status(401).json({
      status: -1,
      message: 'unauthorized',
    });
  }

  public somethingWentWrong(data: ResponsePayload) {
    const { res } = data;

    return res.status(500).json({
      status: -1,
      message: 'something-went-wrong',
    });
  }

  public accessForbidden(data: ResponsePayload) {
    const { res } = data;

    return res.status(403).json({
      status: -1,
      message: 'access-forbidden',
    });
  }
}
