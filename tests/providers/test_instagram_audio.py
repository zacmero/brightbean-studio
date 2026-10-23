import json
import unittest
from unittest.mock import Mock, patch

import httpx
from providers.instagram import InstagramProvider, _audio_configuration
from providers.exceptions import PublishError
from providers.types import PostType, PublishContent


class InstagramAudioTests(unittest.TestCase):
    def setUp(self):
        self.provider = InstagramProvider({"client_id": "test", "client_secret": "test"})
        self.audio = {"audio_id": "550177149656126", "audio_volume": 60, "video_volume": 1}
        self.content = PublishContent(text="Caption", media_urls=["https://media.test/reel.mp4"], post_type=PostType.REEL, extra={"ig_user_id": "sarah", "audio_configuration": self.audio, "cover_url": "https://media.test/cover.jpg"})

    def test_selected_audio_and_cover_reach_container_together(self):
        self.provider._create_container = Mock(return_value="container")
        self.provider._wait_for_container = Mock()
        self.provider._publish_container = Mock()
        self.provider.publish_post("token", self.content)
        payload = self.provider._create_container.call_args.args[2]
        self.assertEqual(payload["audio_configuration"], self.audio)
        self.assertEqual(payload["cover_url"], self.content.extra["cover_url"])
        self.assertEqual(payload["media_type"], "REELS")
        self.assertEqual(self.content.extra["audio_configuration"], self.audio)

    def test_actual_transport_is_json_object_not_python_repr(self):
        bodies = []
        def request(client, method, url, **kwargs):
            wire = httpx.Request(method, url, **{k:v for k,v in kwargs.items() if k in {"json","data","headers","params"}})
            bodies.append(json.loads(wire.content))
            return httpx.Response(200, json={"id": "container"})
        with patch.object(httpx.Client, "request", request):
            self.assertEqual(self.provider._create_container("token", "sarah", {"media_type":"REELS", "audio_configuration":self.audio}), "container")
        self.assertIsInstance(bodies[0]["audio_configuration"], dict)
        self.assertEqual(bodies[0]["audio_configuration"], self.audio)

    def test_no_audio_keeps_existing_payload(self):
        self.content.extra.pop("audio_configuration")
        self.provider._create_container = Mock(return_value="container")
        self.provider._wait_for_container = Mock()
        self.provider._publish_container = Mock()
        self.provider.publish_post("token", self.content)
        self.assertNotIn("audio_configuration", self.provider._create_container.call_args.args[2])

    def test_official_volume_defaults_and_both_final_ids(self):
        for ident in ["550177149656126", "1214305965663814"]:
            self.content.extra["audio_configuration"] = {"audio_id": ident}
            self.assertEqual(_audio_configuration(self.content), {"audio_id":ident, "audio_volume":100, "video_volume":100})

    def test_invalid_configuration_rejected_without_provider_request(self):
        invalid = [{"audio_id":123}, {"audio_id":""}, {"audio_id":"123", "audio_volume":0}, {"audio_id":"123", "video_volume":101}, {"audio_id":"123", "video_volume":True}, {"audio_id":"123", "audio_volume":1.2}, {"audio_id":"123", "unknown":1}]
        for value in invalid:
            self.content.extra["audio_configuration"] = value
            with self.subTest(value=value), patch.object(self.provider, "_request") as request:
                with self.assertRaises(PublishError) as error:
                    self.provider.publish_post("token", self.content)
                self.assertFalse(error.exception.retryable)
                request.assert_not_called()

    def test_library_audio_rejected_for_other_formats(self):
        for kind in [PostType.IMAGE, PostType.STORY, PostType.CAROUSEL]:
            self.content.post_type = kind
            with self.subTest(kind=kind), patch.object(self.provider, "_request") as request:
                with self.assertRaises(PublishError):
                    self.provider.publish_post("token", self.content)
                request.assert_not_called()
