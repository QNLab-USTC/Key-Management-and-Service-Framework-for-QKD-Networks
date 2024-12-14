#include <cstdint>
#include <gsl/gsl_randist.h>
#include <gsl/gsl_rng.h>
#include <iostream>
#include <utility>
#include <vector>
#include <fstream>

unsigned long int gsl_rng_default_seed = 10;

class PPBP
{
public:
  PPBP();
  ~PPBP();

  // 开始和结束时间：ms
  void set_time(int32_t stime, int32_t etime, int32_t seed);

  // ton：ms，突发到达率：个每秒，平均速率：kbps，包大小：字节
  void set_distrib_para(double pareto_hurst, double pareto_Ton,
                        double poisson_arrival_rate, double avg_rate,
                        double pkt_size);

  // [<突发开始时间，突发包个数>]
  std::vector<std::pair<int32_t, int32_t>> ger_all_burst();

private:
  [[deprecated]] int32_t next_send_time();

  void calc_next_slot();

  int32_t get_pareto_number();

  int32_t get_exp_number();

private:
  double par_scale_;
  double par_shape_;
  double exp_mean_;
  double pkt_interval_;
  gsl_rng *gsl_rng_;

  int32_t start_time_;
  int32_t end_time_;

  int32_t cur_burst_start_;
  int32_t cur_burst_end_;

  int32_t next_burst_start_;

  int32_t cur_time_;
};

PPBP::PPBP()
    : start_time_(0), end_time_(1'000),
      gsl_rng_(gsl_rng_alloc(gsl_rng_mt19937)), cur_burst_start_(0),
      cur_burst_end_(0), next_burst_start_(0), cur_time_(0)
{
  //   calc_next_slot();
}

PPBP::~PPBP() { gsl_rng_free(gsl_rng_); }

void PPBP::set_time(int32_t stime, int32_t etime, int32_t seed)
{
  start_time_ = stime;
  end_time_ = etime;
  cur_burst_start_ = cur_burst_end_ = next_burst_start_ = cur_time_ = stime;
  gsl_rng_default_seed = seed;
}

void PPBP::set_distrib_para(double pareto_hurst, double pareto_Ton,
                            double poisson_arrival_rate, double avg_rate,
                            double pkt_size)
{
  par_shape_ = 3 - 2 * pareto_hurst;
  par_scale_ = pareto_Ton;
  exp_mean_ = 1 / poisson_arrival_rate * 1'000;
  pkt_interval_ = pkt_size * 8 / avg_rate;

  std::cout << "par_shape_ = " << par_shape_ << '\n'
            << "par_scale_ = " << par_scale_ << '\n'
            << "exp_mean_ = " << exp_mean_ << '\n'
            << "pkt_interval_ = " << pkt_interval_ << '\n';
}

void PPBP::calc_next_slot()
{
  int n = 0;
  cur_burst_start_ = next_burst_start_;
  do
  {
    n++;
    cur_burst_end_ = next_burst_start_ + get_pareto_number();
    next_burst_start_ += get_exp_number();
  } while (next_burst_start_ <= cur_burst_end_);

  std::cout << "cur_b_s = " << cur_burst_start_ << '\n'
            << "cur_b_e = " << cur_burst_end_ << '\n'
            << "nxt_b_s = " << next_burst_start_ << '\n'
            << "round = " << n << '\n';
}

int32_t PPBP::get_pareto_number()
{
  return gsl_ran_pareto(gsl_rng_, par_shape_, par_scale_);
}

int32_t PPBP::get_exp_number()
{
  return gsl_ran_exponential(gsl_rng_, exp_mean_);
}

int32_t PPBP::next_send_time()
{
  do
  {
    if (cur_time_ >= cur_burst_end_)
    {
      calc_next_slot();
      cur_time_ = cur_burst_start_;
    }

    int32_t ret = cur_time_;
    cur_time_ += pkt_interval_;

    if (cur_time_ > end_time_)
    {
      return -1;
    }

    if (cur_time_ >= cur_burst_start_ && cur_time_ <= cur_burst_end_)
    {
      return ret;
    }
  } while (true);
}

std::vector<std::pair<int32_t, int32_t>> PPBP::ger_all_burst()
{
  std::vector<std::pair<int32_t, int32_t>> ret;
  ret.reserve(50);
  calc_next_slot();
  while (cur_burst_start_ < end_time_)
  {
    int duration = 0;
    if (cur_burst_end_ < end_time_)
    {
      duration = cur_burst_end_ - cur_burst_start_;
    }
    else
    {
      duration = end_time_ - cur_burst_start_;
    }
    int n = duration / pkt_interval_;
    ret.emplace_back(std::make_pair(cur_burst_start_, n));
    calc_next_slot();
  }
  ret.shrink_to_fit();
  return ret;
}

int main(int argc, char *argv[])
{
  std::fstream file;
  if (argc == 2)
  {
    file.open(argv[1], std::ios::out);
  }
  else
  {
    return 0;
  }
  gsl_rng_env_setup();
  auto a = PPBP();
  a.set_time(5000, 600000, 10);
  a.set_distrib_para(0.8, 120, 3.5, 800, 512);
  //   for (int i = 0; i < 50; i++)
  //     std::cout << a.get_pareto_number() << '\n';
  //   std::cout << "go" << '\n';
  //   for (int i = 0; i < 50; i++)
  //     std::cout << a.get_exp_number() << '\n';

  // for (int i = 0; i < 100; i++)
  //   std::cout << a.next_send_time() << '\n';
  int sum = 0;
  for (auto &i : a.ger_all_burst())
  {
    file << i.first << " " << i.second << '\n';
    sum = sum + i.second;
  }
  std::cout << sum * 512 * 8 / 595 / 1000 << std::endl;
  return 0;
}