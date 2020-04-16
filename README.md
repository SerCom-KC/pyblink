# pyblink
bilibili instant message client written in Python, based on TCP socket & Protocol Buffers - less secure but no need to poll their web API  

## License
[AGPL-3.0](https://github.com/SerCom-KC/pyblink/raw/master/LICENSE)  

## Documentation

### blink.Client.send_message()

- `receiver_uid`: `int`, `uid` of the recipient
- `content`: `dict` or `str` (only when `msg_type` is `blink.MsgType.EN_MSG_TYPE_TEXT`)
  - When `msg_type` is `blink.MsgType.EN_MSG_TYPE_TEXT`
    - `content`: `str`
  - When `msg_type` is `blink.MsgType.EN_MSG_TYPE_PIC` or `blink.MsgType.EN_MSG_TYPE_CUSTOM_FACE` (images should be uploaded via `https://api.vc.bilibili.com/api/v1/image/upload`)
    - `height`: `int`, height of the image
    - `imageType`: `str`
      - `gif`: Image is a GIF
      - `png`: Otherwise
    - `original`: `int`
      - `0`: Image was compressed client-side during upload
      - `1`: Otherwise
    - `size`: `str`, size of the image file in kibibytes. Integer string only.
    - `url`: `str`, URL to the image
    - `width`: `int`, width of the image
  - When `msg_type` is `blink.MsgType.EN_MSG_TYPE_SHARE_V2`
    - `author`: `str`, `uname` of the author
    - `headline`: `str`, displayed in bold text above `title`. Empty string allowed.
    - `id`: `int`
      - `source` is `1`: Use the "vc" ID.
      - `source` is `2` or `11`: Use `rid`
      - `source` is `5`: Use `aid`
      - `source` is `6`: Use the "cv" ID
    - `source`: `int`
      - `1`: `im_share_type_video_clip`
      - `2`: `im_share_type_image_text`
      - `4`: `im_share_type_live`
      - `5`: `im_share_type_video_normal`
      - `6`: `im_share_type_article`
      - `7`: `im_share_type_bangumi`
      - `8`: `im_share_type_music`
      - `9`: `im_share_type_domestic`
      - `11`: `im_share_type_dynamic`
      - `12`: `im_share_type_movie`
      - `13`: `im_share_type_drama`
      - `14`: `im_share_type_documentary`
    - `thumb`: `str`
      - `source` is `11`: Image URL to the author's avatar
      - Use thumbnail URL otherwise
    - `title`: `str`
    - `url`: Optional `str`
