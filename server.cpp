#include "common.hpp"
#include "ring_buffer.hpp"

#include <thread>
#include <atomic>
#include <fstream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>
#include <ctime>
#include <cstdlib>
#include <algorithm>
#include <iomanip>
#include <sstream>

static constexpr int PORT = 5050;
static constexpr size_t BUFFER_SIZE = 65536;
static const std::string PRE_SHARED_KEY = "demo_key_123";

static std::string pct(double x){
  std::ostringstream os;
  os << std::fixed << std::setprecision(2) << (x * 100.0) << "%";
  return os.str();
}

static std::string fmt2(double x){
  std::ostringstream os;
  os << std::fixed << std::setprecision(2) << x;
  return os.str();
}

static void handle_client(int cfd, std::string tag){
  log_line("SERVER", "accept " + tag);

  bool encdbg = false;
  int log_every = 50;
  if (const char* e = std::getenv("ENCDBG")) encdbg = (std::atoi(e) != 0);
  if (const char* e = std::getenv("LOG_EVERY")) log_every = std::max(1, std::atoi(e));

  uint64_t total_frames = 0, good_frames = 0, bad_frames = 0;
  uint64_t written_bytes = 0;
  uint64_t expected_total_bytes = 0; // (noise olmasaydı) toplam beklenen dosya baytı: tüm DATA frame payload'larının toplamı

  // Client noise info (HELLO extension ile gelecek)
  bool client_noise_declared = false;
  double client_snr_db = 0.0;
  uint32_t client_noise_seed = 0;

  // 1) Handshake: HELLO (client_nonce [+ snr_x100 + seed]) -> HELLO_ACK (server_nonce)
  FrameHeader h{};
  std::vector<uint8_t> payload;

  if (!recv_frame_raw(cfd, h, payload) ||
      (FrameType)h.type != FrameType::HELLO ||
      !(payload.size() == 4 || payload.size() == 12)) {
    log_line("SERVER", tag + " handshake: bad HELLO");
    ::close(cfd);
    return;
  }

  uint32_t client_nonce = 0;
  std::memcpy(&client_nonce, payload.data(), 4);
  log_line("HANDSHAKE", tag + " client_nonce=" + std::to_string(client_nonce));

  if (payload.size() == 12){
    int32_t snr_x100 = 0;
    std::memcpy(&snr_x100, payload.data() + 4, 4);
    std::memcpy(&client_noise_seed, payload.data() + 8, 4);
    client_snr_db = (double)snr_x100 / 100.0;
    client_noise_declared = true;

    log_line("HANDSHAKE",
      tag + " client_noise declared: SNR(dB)=" + fmt2(client_snr_db) +
      " seed=" + std::to_string(client_noise_seed)
    );
  }

  uint32_t server_nonce = (uint32_t)time(nullptr) ^ (uint32_t)getpid();
  std::vector<uint8_t> ackPayload(4);
  std::memcpy(ackPayload.data(), &server_nonce, 4);

  uint32_t ackCs = checksum_simple(ackPayload.data(), ackPayload.size());
  if (!send_frame_raw(cfd, FrameType::HELLO_ACK, ContentType::BIN, 1, ackPayload, ackCs)){
    log_line("SERVER", tag + " handshake: send HELLO_ACK failed");
    ::close(cfd);
    return;
  }

  auto session_key = derive_session_key(client_nonce, server_nonce, PRE_SHARED_KEY);
  log_line("HANDSHAKE", tag + " session_key derived (len=" + std::to_string(session_key.size()) + ")");
  log_line("SERVER", tag + " encdbg=" + std::to_string((int)encdbg) + " log_every=" + std::to_string(log_every));

  // 2) RingBuffer demo
  RingBuffer rb(BUFFER_SIZE);
  std::atomic<bool> running{true};

  std::thread consumer([&](){
    while (running.load()){
      uint8_t b = 0;
      rb.pop_bytes(&b, 1);
      std::cout << (char)b << std::flush;
      std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
  });

  // 3) File receive state
  std::ofstream outFile;
  bool fileMode = false;
  std::string outName;

  int data_idx = 0;

  while (true){
    FrameHeader fh{};
    std::vector<uint8_t> enc;

    if (!recv_frame_raw(cfd, fh, enc)){
      log_line("SERVER", tag + " closed or recv error");
      break;
    }

    FrameType t = (FrameType)fh.type;

    if (t == FrameType::FIN){
      log_line("SERVER", tag + " FIN seq=" + std::to_string(fh.seq));
      if (fileMode && outFile.is_open()){
        outFile.close();
        log_line("SERVER", tag + " file saved -> " + outName);
      }
      break;
    }

    if (t != FrameType::DATA){
      continue;
    }

    total_frames++;
    expected_total_bytes += fh.payload_len; // hangi durumda olursa olsun "beklenen toplam" artar

    bool do_log = (data_idx % log_every == 0);

    if (encdbg && do_log){
      log_line("ENCDBG", tag + " cipher = " + hex_preview(enc));
    }

    // decrypt
    std::vector<uint8_t> plain = enc;
    xor_crypt_inplace(plain, session_key);

    if (encdbg && do_log){
      log_line("ENCDBG", tag + " plain  = " + hex_preview(plain));
    }

    // checksum verify
    uint32_t cs = checksum_simple(plain.data(), plain.size());
    if (cs != fh.checksum){
      bad_frames++;
      if (do_log){
        log_line("SERVER", tag + " CHECKSUM MISMATCH seq=" + std::to_string(fh.seq));
      }
      data_idx++;
      continue;
    }

    good_frames++;

    if (do_log){
      log_line("SERVER",
        tag + " DATA seq=" + std::to_string(fh.seq) +
        " len=" + std::to_string(plain.size()) +
        " ctype=" + std::to_string((int)fh.content_type)
      );
    }

    ContentType ct = (ContentType)fh.content_type;

    if (ct == ContentType::BIN){
      if (!fileMode){
        outName = "received_" + tag + ".bin";
        for (char& ch : outName){
          if (ch == ':' || ch == '/') ch = '_';
        }

        outFile.open(outName, std::ios::binary);
        if (!outFile){
          data_idx++;
          continue;
        }
        fileMode = true;
        log_line("SERVER", tag + " file receive started -> " + outName);
      }

      if (!plain.empty()){
        outFile.write(reinterpret_cast<const char*>(plain.data()), (std::streamsize)plain.size());
        written_bytes += plain.size();
      }
    } else {
      if (!plain.empty()){
        rb.push_bytes(plain.data(), plain.size());
        uint8_t nl = '\n';
        rb.push_bytes(&nl, 1);
      }
    }

    data_idx++;
  }

  double fer = (total_frames == 0) ? 0.0 : (double)bad_frames / (double)total_frames;
  double success_ratio = (expected_total_bytes == 0) ? 0.0 : (double)written_bytes / (double)expected_total_bytes;
  double loss_ratio = 1.0 - success_ratio;

  std::string noise_part = client_noise_declared
    ? (" client_SNR(dB)=" + fmt2(client_snr_db) + " seed=" + std::to_string(client_noise_seed))
    : (" client_SNR(dB)=N/A seed=N/A");

  log_line("STATS",
           tag +
           " total=" + std::to_string(total_frames) +
           " good=" + std::to_string(good_frames) +
           " bad=" + std::to_string(bad_frames) +
           " FER=" + pct(fer) +
           " expected_bytes=" + std::to_string(expected_total_bytes) +
           " written_bytes=" + std::to_string(written_bytes) +
           " loss=" + pct(loss_ratio) +
           noise_part
  );

  running.store(false);
  ::shutdown(cfd, SHUT_RDWR);
  ::close(cfd);
  consumer.detach();
  log_line("SERVER", "client end " + tag);
}

int main(){
  signal(SIGPIPE, SIG_IGN);

  int sfd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (sfd < 0){ perror("socket"); return 1; }

  int opt = 1;
  setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(PORT);

  if (bind(sfd, (sockaddr*)&addr, sizeof(addr)) < 0){ perror("bind"); return 1; }
  if (listen(sfd, 16) < 0){ perror("listen"); return 1; }

  log_line("SERVER", "listening on :" + std::to_string(PORT));

  while (true){
    sockaddr_in caddr{};
    socklen_t clen = sizeof(caddr);
    int cfd = accept(sfd, (sockaddr*)&caddr, &clen);
    if (cfd < 0){ perror("accept"); continue; }

    char ipbuf[64];
    inet_ntop(AF_INET, &caddr.sin_addr, ipbuf, sizeof(ipbuf));
    std::string tag = std::string(ipbuf) + ":" + std::to_string(ntohs(caddr.sin_port));

    std::thread(handle_client, cfd, tag).detach();
  }

  ::close(sfd);
  return 0;
}
