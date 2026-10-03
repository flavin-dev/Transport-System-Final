import 'dart:async';
import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import '../api/api_client.dart';
import '../auth/session.dart';
import '../config.dart';

/// A message from the server hub: {"type": "notification" | "ops" | "boarding", "data": {...}}.
class LiveMessage {
  const LiveMessage(this.type, this.data);

  final String type;
  final Json data;

  /// For `ops` messages: the domain event name, e.g. "TripDelayed".
  String? get event => data['event'] as String?;
  Json get payload => (data['payload'] as Json?) ?? const {};
}

/// Keeps one WebSocket open while signed in. Reconnects with backoff and
/// re-subscribes to topics. Always uses the *current* access token on (re)connect.
class RealtimeClient {
  RealtimeClient(this._token) {
    _connect();
  }

  final String? Function() _token;
  final _out = StreamController<LiveMessage>.broadcast();
  final _topics = <String>{};
  WebSocketChannel? _ch;
  StreamSubscription? _sub;
  Timer? _ping;
  Timer? _retry;
  var _attempt = 0;
  var _closed = false;

  Stream<LiveMessage> get messages => _out.stream;

  void subscribe(String topic) {
    if (_topics.add(topic)) _send({'action': 'subscribe', 'topic': topic});
  }

  void unsubscribe(String topic) {
    if (_topics.remove(topic)) _send({'action': 'unsubscribe', 'topic': topic});
  }

  void _send(Map<String, dynamic> m) {
    try {
      _ch?.sink.add(jsonEncode(m));
    } catch (_) {
      /* reconnect will re-send topics */
    }
  }

  Future<void> _connect() async {
    final token = _token();
    if (_closed || token == null) return;
    try {
      final ch = WebSocketChannel.connect(Uri.parse('${AppConfig.wsBase}/ws'));
      await ch.ready;
      ch.sink.add(jsonEncode({'token': token}));
      _ch = ch;
      _attempt = 0;
      for (final t in _topics) {
        _send({'action': 'subscribe', 'topic': t});
      }
      _sub = ch.stream.listen(
        (raw) {
          final m = jsonDecode(raw as String) as Json;
          final type = m['type'] as String;
          if (type != 'pong') _out.add(LiveMessage(type, (m['data'] as Json?) ?? const {}));
        },
        onDone: _scheduleReconnect,
        onError: (_) => _scheduleReconnect(),
      );
      _ping = Timer.periodic(const Duration(seconds: 25), (_) => _send({'action': 'ping'}));
    } catch (_) {
      _scheduleReconnect();
    }
  }

  void _scheduleReconnect() {
    _ping?.cancel();
    _sub?.cancel();
    _ch = null;
    if (_closed) return;
    final secs = [1, 2, 4, 8, 15, 20][_attempt.clamp(0, 5)];
    _attempt++;
    _retry?.cancel();
    _retry = Timer(Duration(seconds: secs), _connect);
  }

  void dispose() {
    _closed = true;
    _retry?.cancel();
    _ping?.cancel();
    _sub?.cancel();
    _ch?.sink.close();
    _out.close();
  }
}

/// One client per signed-in user. Token refreshes don't recreate it: the client reads the
/// latest access token on every (re)connect, and the server closes sockets whose token expired.
final realtimeProvider = Provider<RealtimeClient?>((ref) {
  final userId = ref.watch(sessionProvider.select((s) => s?.user.id));
  if (userId == null) return null;
  final client = RealtimeClient(() => ref.read(sessionProvider)?.accessToken);
  ref.onDispose(client.dispose);
  return client;
});

final liveMessagesProvider = StreamProvider<LiveMessage>((ref) {
  final client = ref.watch(realtimeProvider);
  return client?.messages ?? const Stream.empty();
});

/// Call from a ConsumerWidget's build: re-run [onChange] when a relevant live message arrives.
void listenLive(WidgetRef ref, void Function(LiveMessage m) onChange, {Set<String>? events}) {
  ref.listen<AsyncValue<LiveMessage>>(liveMessagesProvider, (_, next) {
    final m = next.asData?.value;
    if (m == null) return;
    if (events == null || events.contains(m.event) || (m.type != 'ops' && events.contains(m.type))) {
      onChange(m);
    }
  });
}
